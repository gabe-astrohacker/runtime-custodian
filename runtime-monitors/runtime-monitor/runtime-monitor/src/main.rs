use log::{debug, warn};
use std::borrow::Cow;
use tokio::signal;

use aya::{Ebpf, include_bytes_aligned, maps::RingBuf, programs::TracePoint};
use runtime_monitor_common::{Event, EventType};

fn event_type_name(v: u32) -> &'static str {
    match v {
        x if x == EventType::Fork as u32 => "fork",
        x if x == EventType::Exec as u32 => "exec",
        _ => "unknown",
    }
}

fn bytes_to_string(bytes: &[u8]) -> Cow<'_, str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/runtime-monitor"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // let fork_prog: &mut TracePoint = ebpf
    //     .program_mut("sched_process_fork")
    //     .ok_or_else(|| anyhow::anyhow!("program sched_process_fork not found"))?
    //     .try_into()?;
    // fork_prog.load()?;
    // fork_prog.attach("sched", "sched_process_fork")?;

    let exec_prog: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .ok_or_else(|| anyhow::anyhow!("program sched_process_exec not found"))?
        .try_into()?;
    exec_prog.load()?;
    exec_prog.attach("sched", "sched_process_exec")?;

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
    )?;

    println!("Listening for events... press Ctrl-C to stop.");

    let ctrl_c = signal::ctrl_c();

    tokio::pin!(ctrl_c);

    loop {
        if let Some(item) = ring.next() {
            let bytes = &item;

            if bytes.len() != core::mem::size_of::<Event>() {
                continue;
            }

            let ev = *bytemuck::from_bytes::<Event>(bytes);

            let comm = bytes_to_string(&ev.comm);
            if !matches!(
                comm.as_ref(),
                "python" | "python3" | "uvicorn" | "echo" | "id"
            ) {
                continue;
            }

            let exe_path = bytes_to_string(&ev.filename);

            println!(
                "{{\"type\":\"{}\",\"pid\":{},\"tgid\":{},\"ppid\":{},\"cpu\":{},\"cgroup_id\":{},\"comm\":\"{}\",\"exe_path\":\"{}\"}}",
                event_type_name(ev.event_type),
                ev.pid,
                ev.tgid,
                ev.ppid,
                ev.cpu,
                ev.cgroup_id,
                comm,
                exe_path,
            );
        } else {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
    }
    Ok(())
}
