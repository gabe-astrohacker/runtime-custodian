#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

use core::ptr;

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use runtime_monitor_common::{
    COLLECTION_MODE_HOST_WIDE, Event, EventType, FILENAME_TRUNCATED, MonitorState, PATH_LEN,
    TargetWorkload, UNKNOWN_WORKLOAD_INDEX,
};

#[map(name = "TARGET_CGROUPS")]
static TARGET_CGROUPS: HashMap<u64, TargetWorkload> = HashMap::with_max_entries(1024, 0);

#[map(name = "COLLECTION_MODE")]
static COLLECTION_MODE: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "MONITOR_STATE")]
static MONITOR_STATE: Array<MonitorState> = Array::with_max_entries(1, 0);

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

unsafe fn atomic_fetch_add_u64(ptr: *mut u64, value: u64) -> u64 {
    // Shared across CPUs: must compile to a single BPF atomic add/fetch-add,
    // not a racy load/add/store and not an unbounded CAS loop.
    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            ptr, value,
        )
    }
}

// #[tracepoint]
// pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
//     match try_sched_process_fork(ctx) {
//         Ok(ret) => ret,
//         Err(_) => 0,
//     }
// }

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, i64> {
//     // tracepoint layout from kernel:
//     // common fields first, then parent_comm[16], parent_pid, child_comm[16], child_pid
//     let parent_pid: u32 = unsafe { ctx.read_at::<u32>(24)? };
//     let child_pid: u32 = unsafe { ctx.read_at::<u32>(44)? };

//     emit_event(EventType::Fork, child_pid, child_pid, parent_pid)
// }

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let mode = COLLECTION_MODE.get(0).copied().unwrap_or_default();
    let workload = unsafe { TARGET_CGROUPS.get(&cgroup_id) };

    let (workload_index, workload_flags) = match workload {
        Some(workload) => (workload.workload_index, workload.flags),
        None if mode == COLLECTION_MODE_HOST_WIDE => (UNKNOWN_WORKLOAD_INDEX, 0),
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    // bpf_get_current_pid_tgid returns TGID in the upper 32 bits and PID in the lower 32 bits.
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // sched_process_exec format: common fields, old_pid, pid, then __data_loc filename at offset 8.
    let filename_loc: u32 = unsafe { ctx.read_at::<u32>(8)? };
    let filename_offset = filename_loc & 0xffff;

    let filename_ptr = unsafe { ctx.as_ptr().add(filename_offset as usize) as *const u8 };

    emit_event(
        EventType::Exec,
        cgroup_id,
        workload_index,
        workload_flags,
        pid,
        tgid,
        0,
        filename_ptr,
    )
}

fn emit_event(
    event_type: EventType,
    cgroup_id: u64,
    workload_index: u32,
    workload_flags: u32,
    pid: u32,
    tgid: u32,
    ppid: u32,
    filename_ptr: *const u8,
) -> Result<u32, i64> {
    let state = MONITOR_STATE.get_ptr_mut(0).ok_or(0_i64)?;

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => {
            unsafe {
                atomic_fetch_add_u64(ptr::addr_of_mut!((*state).lost), 1);
            }
            return Ok(0);
        }
    };
    let seq = unsafe { atomic_fetch_add_u64(ptr::addr_of_mut!((*state).seq), 1) };

    let comm = bpf_get_current_comm().unwrap_or_default();
    let mut filename_len = 0u32;
    let mut filename_flags = 0u32;
    let mut filename_read_error = 0i32;

    let event = entry.as_mut_ptr();
    unsafe {
        ptr::write_bytes(event.cast::<u8>(), 0, core::mem::size_of::<Event>());
        ptr::addr_of_mut!((*event).seq).write(seq);
        // Per-event lost counts stay zero; the shared map retains the global lost counter
        // for the final summary, which avoids verifier rejection of nonzero lost samples.
        ptr::addr_of_mut!((*event).lost).write(0);
        ptr::addr_of_mut!((*event).ts_ns).write(bpf_ktime_get_ns());
        ptr::addr_of_mut!((*event).cgroup_id).write(cgroup_id);
        ptr::addr_of_mut!((*event).event_type).write(event_type as u32);
        ptr::addr_of_mut!((*event).pid).write(pid);
        ptr::addr_of_mut!((*event).tgid).write(tgid);
        ptr::addr_of_mut!((*event).ppid).write(ppid);
        ptr::addr_of_mut!((*event).cpu).write(bpf_get_smp_processor_id());
        ptr::addr_of_mut!((*event).workload_index).write(workload_index);
        ptr::addr_of_mut!((*event).workload_flags).write(workload_flags);
        ptr::addr_of_mut!((*event).comm).write(comm);

        if !filename_ptr.is_null() {
            let filename = core::slice::from_raw_parts_mut(
                ptr::addr_of_mut!((*event).filename).cast::<u8>(),
                PATH_LEN,
            );
            match bpf_probe_read_kernel_str_bytes(filename_ptr, filename) {
                Ok(bytes) => {
                    filename_len = bytes.len() as u32;
                    if bytes.len() >= PATH_LEN - 1 {
                        filename_flags = FILENAME_TRUNCATED;
                    }
                }
                Err(error) => {
                    filename_read_error = error;
                }
            }
        } else {
            filename_read_error = -1;
        }

        ptr::addr_of_mut!((*event).filename_len).write(filename_len);
        ptr::addr_of_mut!((*event).filename_flags).write(filename_flags);
        ptr::addr_of_mut!((*event).filename_read_error).write(filename_read_error);
        ptr::addr_of_mut!((*event).reserved).write(0);
        ptr::addr_of_mut!((*event).reserved2).write(0);
    }

    entry.submit(0);
    Ok(0)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}
