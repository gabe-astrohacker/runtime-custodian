#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use runtime_monitor_common::{Event, EventType, PATH_LEN};

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = pid_tgid as u32;
    let pid = (pid_tgid >> 32) as u32;

    let filename_loc: u32 = unsafe { ctx.read_at::<u32>(8)? };
    let filename_offset = filename_loc & 0xffff;

    let filename_ptr = unsafe { ctx.as_ptr().add(filename_offset as usize) as *const u8 };

    emit_event(EventType::Exec, pid, tgid, 0, filename_ptr)
}

fn emit_event(
    event_type: EventType,
    pid: u32,
    tgid: u32,
    ppid: u32,
    filename_ptr: *const u8,
) -> Result<u32, i64> {
    let mut entry = EVENTS.reserve::<Event>(0).ok_or(0_i64)?;
    let comm = bpf_get_current_comm().unwrap_or_default();

    let mut filename = [0u8; PATH_LEN];
    if !filename_ptr.is_null() {
        unsafe {
            let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut filename);
        }
    }
    entry.write(Event {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        event_type: event_type as u32,
        pid,
        tgid,
        ppid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        reserved: 0,
        comm,
        filename,
    });

    entry.submit(0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
