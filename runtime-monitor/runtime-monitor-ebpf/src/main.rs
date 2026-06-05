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
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use runtime_monitor_common::{
    ARG_LEN, COLLECTION_MODE_HOST_WIDE, Event, EventType, FILENAME_TRUNCATED, MAX_ARGS,
    MonitorState, PATH_LEN, TargetWorkload, UNKNOWN_WORKLOAD_INDEX,
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

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// TODO(Stage 9B follow-up): add sys_enter_execveat capture once its tracepoint
// layout is verified for the target kernels.

// fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, i64> {
//     // tracepoint layout from kernel:
//     // common fields first, then parent_comm[16], parent_pid, child_comm[16], child_pid
//     let parent_pid: u32 = unsafe { ctx.read_at::<u32>(24)? };
//     let child_pid: u32 = unsafe { ctx.read_at::<u32>(44)? };

//     emit_event(EventType::Fork, child_pid, child_pid, parent_pid)
// }

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let Some(scope) = current_scope() else {
        return Ok(0);
    };

    // sched_process_exec format: common fields, old_pid, pid, then __data_loc filename at offset 8.
    let filename_loc: u32 = unsafe { ctx.read_at::<u32>(8)? };
    let filename_offset = filename_loc & 0xffff;

    let filename_ptr = unsafe { ctx.as_ptr().add(filename_offset as usize) as *const u8 };

    Ok(emit_event(
        EventType::Exec,
        scope,
        filename_ptr,
        FilenameSource::Kernel,
        ptr::null(),
    ))
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let Some(scope) = current_scope() else {
        return Ok(0);
    };

    // syscalls/sys_enter_execve format on common kernels:
    //   offset 8:  __syscall_nr
    //   offset 16: const char *filename
    //   offset 24: const char *const *argv
    //   offset 32: const char *const *envp
    // Verify these offsets against
    // /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
    // or /sys/kernel/tracing/events/syscalls/sys_enter_execve/format on the target host.
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<*const u8>(16)? };
    let argv_ptr: *const *const u8 = unsafe { ctx.read_at::<*const *const u8>(24)? };

    Ok(emit_event(
        EventType::ExecAttempt,
        scope,
        filename_ptr,
        FilenameSource::User,
        argv_ptr,
    ))
}

#[derive(Clone, Copy)]
struct Scope {
    cgroup_id: u64,
    workload_index: u32,
    workload_flags: u32,
}

fn current_scope() -> Option<Scope> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let mode = COLLECTION_MODE.get(0).copied().unwrap_or_default();
    let workload = unsafe { TARGET_CGROUPS.get(&cgroup_id) };

    match workload {
        Some(workload) => Some(Scope {
            cgroup_id,
            workload_index: workload.workload_index,
            workload_flags: workload.flags,
        }),
        None if mode == COLLECTION_MODE_HOST_WIDE => Some(Scope {
            cgroup_id,
            workload_index: UNKNOWN_WORKLOAD_INDEX,
            workload_flags: 0,
        }),
        None => None,
    }
}

#[derive(Clone, Copy)]
enum FilenameSource {
    Kernel,
    User,
}

fn emit_event(
    event_type: EventType,
    scope: Scope,
    filename_ptr: *const u8,
    filename_source: FilenameSource,
    argv_ptr: *const *const u8,
) -> u32 {
    let Some(state) = MONITOR_STATE.get_ptr_mut(0) else {
        return 0;
    };

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(entry) => entry,
        None => {
            unsafe {
                atomic_fetch_add_u64(ptr::addr_of_mut!((*state).lost), 1);
            }
            return 0;
        }
    };
    let seq = unsafe { atomic_fetch_add_u64(ptr::addr_of_mut!((*state).seq), 1) };
    let pid_tgid = bpf_get_current_pid_tgid();
    // bpf_get_current_pid_tgid returns TGID in the upper 32 bits and PID in the lower 32 bits.
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

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
        ptr::addr_of_mut!((*event).cgroup_id).write(scope.cgroup_id);
        ptr::addr_of_mut!((*event).event_type).write(event_type as u32);
        ptr::addr_of_mut!((*event).pid).write(pid);
        ptr::addr_of_mut!((*event).tgid).write(tgid);
        ptr::addr_of_mut!((*event).ppid).write(0);
        ptr::addr_of_mut!((*event).cpu).write(bpf_get_smp_processor_id());
        ptr::addr_of_mut!((*event).workload_index).write(scope.workload_index);
        ptr::addr_of_mut!((*event).workload_flags).write(scope.workload_flags);
        ptr::addr_of_mut!((*event).comm).write(comm);

        if !filename_ptr.is_null() {
            let filename = core::slice::from_raw_parts_mut(
                ptr::addr_of_mut!((*event).filename).cast::<u8>(),
                PATH_LEN,
            );
            let read_result = match filename_source {
                FilenameSource::Kernel => bpf_probe_read_kernel_str_bytes(filename_ptr, filename),
                FilenameSource::User => bpf_probe_read_user_str_bytes(filename_ptr, filename),
            };
            match read_result {
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
        ptr::addr_of_mut!((*event).argv_complete).write(0);
        ptr::addr_of_mut!((*event).argv_truncated).write(0);
        ptr::addr_of_mut!((*event).argv_read_error).write(0);
        ptr::addr_of_mut!((*event).argv_reserved2).write(0);

        if event_type as u32 == EventType::ExecAttempt as u32 {
            let mut argc = 0u32;
            let mut argv_complete = 0u32;
            let mut argv_truncated = 0u32;
            let mut argv_read_error = 0i32;
            let argv_base = ptr::addr_of_mut!((*event).argv).cast::<u8>();

            if argv_ptr.is_null() {
                argv_read_error = -1;
            } else {
                for i in 0..MAX_ARGS {
                    let arg_ptr_ptr = argv_ptr.add(i);
                    let arg_ptr = match bpf_probe_read_user::<*const u8>(arg_ptr_ptr) {
                        Ok(arg_ptr) => arg_ptr,
                        Err(error) => {
                            argv_read_error = error as i32;
                            break;
                        }
                    };
                    if arg_ptr.is_null() {
                        argv_complete = 1;
                        break;
                    }

                    let arg_dst =
                        core::slice::from_raw_parts_mut(argv_base.add(i * ARG_LEN), ARG_LEN);
                    match bpf_probe_read_user_str_bytes(arg_ptr, arg_dst) {
                        Ok(bytes) => {
                            if bytes.len() >= ARG_LEN - 1 {
                                argv_truncated = 1;
                            }
                            argc += 1;
                        }
                        Err(error) => {
                            argv_read_error = error as i32;
                            break;
                        }
                    }
                }

                if argv_complete == 0 && argv_read_error == 0 && argc == MAX_ARGS as u32 {
                    match bpf_probe_read_user::<*const u8>(argv_ptr.add(MAX_ARGS)) {
                        Ok(next_ptr) => {
                            if next_ptr.is_null() {
                                argv_complete = 1;
                            } else {
                                argv_truncated = 1;
                            }
                        }
                        Err(error) => {
                            argv_read_error = error as i32;
                        }
                    }
                }
            }

            ptr::addr_of_mut!((*event).argc).write(argc);
            ptr::addr_of_mut!((*event).argv_complete).write(argv_complete);
            ptr::addr_of_mut!((*event).argv_truncated).write(argv_truncated);
            ptr::addr_of_mut!((*event).argv_read_error).write(argv_read_error);
        }
    }

    entry.submit(0);
    0
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}
