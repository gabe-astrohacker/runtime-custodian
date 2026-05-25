use anyhow::{Result, anyhow};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap, RingBuf},
    programs::TracePoint,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::signal;

use runtime_monitor_common::{Event, EventType, TargetWorkload};

#[repr(C)]
struct CgroupFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    handle: [u8; 8],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadConfig {
    workload_id: String,
    container_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleCollectorConfig {
    workload_id: String,
    container_name: String,
    scope: String,
    evidence_out: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiCollectorConfig {
    workloads: Vec<WorkloadConfig>,
    scope: Option<String>,
    evidence_out: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CollectorConfig {
    Single(SingleCollectorConfig),
    Multi(MultiCollectorConfig),
}

impl CollectorConfig {
    fn workloads(&self) -> Vec<WorkloadConfig> {
        match self {
            Self::Single(config) => vec![WorkloadConfig {
                workload_id: config.workload_id.clone(),
                container_name: config.container_name.clone(),
            }],
            Self::Multi(config) => config.workloads.clone(),
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Single(config) => format!(
                "workload_id={} container_name={} scope={} evidence_out={}",
                config.workload_id, config.container_name, config.scope, config.evidence_out
            ),
            Self::Multi(config) => format!(
                "workloads={} scope={} evidence_out={}",
                config.workloads.len(),
                config.scope.as_deref().unwrap_or("<unset>"),
                config.evidence_out.as_deref().unwrap_or("<unset>")
            ),
        }
    }

    fn evidence_out(&self) -> Result<&str> {
        match self {
            Self::Single(config) => Ok(&config.evidence_out),
            Self::Multi(config) => config.evidence_out.as_deref().ok_or_else(|| {
                anyhow!("collector config with `workloads` must set `evidence_out`")
            }),
        }
    }
}

#[derive(Serialize)]
struct EvidenceEvent<'a> {
    workload_id: &'a str,
    workload_index: u32,
    event_type: &'static str,
    pid: u32,
    tgid: u32,
    cgroup_id: u64,
    comm: Cow<'a, str>,
    exe_path: Cow<'a, str>,
    filename_read_ok: bool,
    filename_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename_read_error: Option<i32>,
    ts_ns: u64,
}

fn load_collector_config(path: impl AsRef<Path>) -> Result<CollectorConfig> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    serde_json::from_reader(file).map_err(|e| {
        anyhow!(
            "failed to parse {} as collector config: {e}",
            path.display()
        )
    })
}

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

fn docker_container_pid(container_name: &str) -> Result<u32> {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Pid}}", container_name])
        .output()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                anyhow!("Docker is not available: failed to execute `docker`")
            } else {
                anyhow!("Docker is not available: failed to run docker inspect: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.contains("Cannot connect to the Docker daemon") {
            return Err(anyhow!(
                "Docker is not available: docker daemon is not reachable"
            ));
        }

        return Err(anyhow!(
            "failed to inspect Docker container `{container_name}`: {stderr}"
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid = stdout.trim().parse::<u32>().map_err(|e| {
        anyhow!(
            "failed to parse Docker init PID for container `{container_name}` from `{}`: {e}",
            stdout.trim()
        )
    })?;

    if pid == 0 {
        return Err(anyhow!(
            "container `{container_name}` is not running: Docker reported init PID 0"
        ));
    }

    Ok(pid)
}

fn cgroup_v2_path_for_pid(pid: u32) -> Result<String> {
    let proc_cgroup = format!("/proc/{pid}/cgroup");
    let cgroup = fs::read_to_string(&proc_cgroup)
        .map_err(|e| anyhow!("failed to read {proc_cgroup}: {e}"))?;

    for line in cgroup.lines() {
        if let Some(path) = line.strip_prefix("0::")
            && !path.is_empty()
        {
            return Ok(path.to_owned());
        }
    }

    Err(anyhow!(
        "cgroup v2 path cannot be found in {proc_cgroup}: no `0::<path>` entry"
    ))
}

fn cgroup_mount_path(cgroup_path: &str) -> PathBuf {
    let mut path = PathBuf::from("/sys/fs/cgroup");
    let relative = cgroup_path.trim_start_matches('/');
    if !relative.is_empty() {
        path.push(relative);
    }
    path
}

fn cgroup_id_from_path(path: &Path) -> Result<u64> {
    let path_str = path.to_str().ok_or_else(|| {
        anyhow!(
            "name_to_handle_at failed for cgroup path {}: path is not valid UTF-8",
            path.display()
        )
    })?;
    let c_path = CString::new(path_str).map_err(|e| {
        anyhow!(
            "name_to_handle_at failed for cgroup path {}: {e}",
            path.display()
        )
    })?;

    let mut mount_id = 0;
    let mut handle = CgroupFileHandle {
        handle_bytes: 8,
        handle_type: 0,
        handle: [0; 8],
    };

    let ret = unsafe {
        libc::name_to_handle_at(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            &mut handle as *mut CgroupFileHandle as *mut libc::file_handle,
            &mut mount_id,
            0,
        )
    };

    if ret != 0 {
        return Err(anyhow!(
            "name_to_handle_at failed for cgroup path {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }

    if handle.handle_bytes != 8 {
        return Err(anyhow!(
            "name_to_handle_at failed for cgroup path {}: expected 8-byte cgroup handle, got {} bytes",
            path.display(),
            handle.handle_bytes
        ));
    }

    Ok(u64::from_ne_bytes(handle.handle))
}

fn discover_workload_cgroup_id(workload: &WorkloadConfig) -> Result<u64> {
    let pid = docker_container_pid(&workload.container_name)?;
    let cgroup_path = cgroup_v2_path_for_pid(pid)?;
    let path = cgroup_mount_path(&cgroup_path);
    cgroup_id_from_path(&path).map_err(|e| {
        anyhow!(
            "failed to discover cgroup ID for workload `{}` container `{}`: {e}",
            workload.workload_id,
            workload.container_name
        )
    })
}

fn populate_target_cgroups(ebpf: &mut Ebpf, config: &CollectorConfig) -> Result<()> {
    let mut target_cgroups: HashMap<_, u64, TargetWorkload> = HashMap::try_from(
        ebpf.map_mut("TARGET_CGROUPS")
            .ok_or_else(|| anyhow!("TARGET_CGROUPS map not found"))?,
    )?;

    let workloads = config.workloads();
    for (workload_index, workload) in workloads.iter().enumerate() {
        let cgroup_id = discover_workload_cgroup_id(workload)?;
        target_cgroups.insert(
            cgroup_id,
            TargetWorkload {
                workload_index: workload_index as u32,
                flags: 0,
            },
            0,
        )?;
        info!(
            "target workload indexed: workload_id={} container_name={} cgroup_id={} workload_index={}",
            workload.workload_id, workload.container_name, cgroup_id, workload_index
        );
    }

    Ok(())
}

fn create_evidence_writer(path: impl AsRef<Path>) -> Result<BufWriter<File>> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "failed to create evidence output directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| anyhow!("failed to open evidence output {}: {e}", path.display()))?;

    Ok(BufWriter::new(file))
}

fn workload_id_for_index(workloads: &[WorkloadConfig], workload_index: u32) -> Result<&str> {
    workloads
        .get(workload_index as usize)
        .map(|workload| workload.workload_id.as_str())
        .ok_or_else(|| {
            anyhow!(
                "received event with unknown workload_index {}",
                workload_index
            )
        })
}

fn evidence_event_from_raw<'a>(
    ev: &'a Event,
    workloads: &'a [WorkloadConfig],
) -> Result<EvidenceEvent<'a>> {
    let workload_id = workload_id_for_index(workloads, ev.workload_index)?;
    let event_type = event_type_name(ev.event_type);
    let comm = bytes_to_string(&ev.comm);
    let exe_path = bytes_to_string(&ev.filename);
    let filename_read_error = if ev.filename_read_error == 0 {
        None
    } else {
        Some(ev.filename_read_error)
    };

    Ok(EvidenceEvent {
        workload_id,
        workload_index: ev.workload_index,
        event_type,
        pid: ev.pid,
        tgid: ev.tgid,
        cgroup_id: ev.cgroup_id,
        comm,
        exe_path,
        filename_read_ok: ev.filename_read_error == 0,
        filename_truncated: ev.filename_flags & runtime_monitor_common::FILENAME_TRUNCATED != 0,
        filename_read_error,
        ts_ns: ev.ts_ns,
    })
}

fn write_evidence_event(writer: &mut BufWriter<File>, evidence: &EvidenceEvent<'_>) -> Result<()> {
    serde_json::to_writer(&mut *writer, evidence)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn config_path_from_args() -> Option<String> {
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        if let Some(path) = arg.strip_prefix("--config=") {
            return Some(path.to_owned());
        }

        if let Some(path) = arg.strip_prefix("--collector-config=") {
            return Some(path.to_owned());
        }

        if arg == "--config" || arg == "--collector-config" {
            return args.next();
        }
    }

    None
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let collector_config = if let Some(path) = config_path_from_args() {
        let config = load_collector_config(path)?;
        info!("loaded collector config: {}", config.summary());
        config
    } else {
        return Err(anyhow!(
            "collector config is required; pass --collector-config <collector_config.json>"
        ));
    };
    let workloads = collector_config.workloads();
    let mut evidence_writer = create_evidence_writer(collector_config.evidence_out()?)?;

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

    populate_target_cgroups(&mut ebpf, &collector_config)?;

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
    //     .ok_or_else(|| anyhow!("program sched_process_fork not found"))?
    //     .try_into()?;
    // fork_prog.load()?;
    // fork_prog.attach("sched", "sched_process_fork")?;

    let exec_prog: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .ok_or_else(|| anyhow!("program sched_process_exec not found"))?
        .try_into()?;
    exec_prog.load()?;
    exec_prog.attach("sched", "sched_process_exec")?;

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS map not found"))?,
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

            let evidence = evidence_event_from_raw(&ev, &workloads)?;
            write_evidence_event(&mut evidence_writer, &evidence)?;

            println!(
                "{} workload={} index={} pid={} comm={} exe_path={}",
                evidence.event_type,
                evidence.workload_id,
                evidence.workload_index,
                evidence.pid,
                evidence.comm,
                evidence.exe_path,
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
