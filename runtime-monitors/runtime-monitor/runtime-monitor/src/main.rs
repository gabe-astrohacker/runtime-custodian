use anyhow::{Result, anyhow};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array as BpfArray, HashMap, RingBuf},
    programs::TracePoint,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::signal;

use runtime_monitor_common::{
    COLLECTION_MODE_HOST_WIDE, COLLECTION_MODE_SCOPED, Event, EventType, MonitorState,
    TargetWorkload, UNKNOWN_WORKLOAD_INDEX,
};

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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CollectionMode {
    Scoped,
    HostWide,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleCollectorConfig {
    workload_id: String,
    container_name: String,
    collection_mode: Option<CollectionMode>,
    evidence_out: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiCollectorConfig {
    workloads: Vec<WorkloadConfig>,
    collection_mode: Option<CollectionMode>,
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
                "workload_id={} container_name={} collection_mode={} evidence_out={}",
                config.workload_id,
                config.container_name,
                config
                    .collection_mode
                    .unwrap_or(CollectionMode::Scoped)
                    .as_str(),
                config.evidence_out
            ),
            Self::Multi(config) => format!(
                "workloads={} collection_mode={} evidence_out={}",
                config.workloads.len(),
                config
                    .collection_mode
                    .unwrap_or(CollectionMode::Scoped)
                    .as_str(),
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

    fn collection_mode(&self) -> Result<CollectionMode> {
        match self {
            Self::Single(config) => Ok(config.collection_mode.unwrap_or(CollectionMode::Scoped)),
            Self::Multi(config) => Ok(config.collection_mode.unwrap_or(CollectionMode::Scoped)),
        }
    }
}

impl CollectionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scoped => "scoped",
            Self::HostWide => "host-wide",
        }
    }

    fn as_bpf_value(self) -> u32 {
        match self {
            Self::Scoped => COLLECTION_MODE_SCOPED,
            Self::HostWide => COLLECTION_MODE_HOST_WIDE,
        }
    }
}

#[derive(Serialize)]
struct EvidenceEvent<'a> {
    seq: u64,
    lost: u64,
    workload_id: Option<&'a str>,
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

#[derive(Serialize)]
struct EvidenceSummary<'a> {
    workload_id: Option<&'a str>,
    collection_mode: &'a str,
    event_count: usize,
    evidence_digest: String,
    final_seq: u64,
    final_lost: u64,
    malformed_samples: usize,
}

impl EvidenceSummary<'_> {
    fn write_to(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| anyhow!("failed to create evidence summary {}: {e}", path.display()))?;
        serde_json::to_writer_pretty(BufWriter::new(file), self)
            .map_err(|e| anyhow!("failed to write evidence summary {}: {e}", path.display()))
    }
}

struct RollingDigest {
    value: [u8; 32],
}

impl RollingDigest {
    fn new() -> Self {
        Self { value: [0; 32] }
    }

    fn update(&mut self, raw_event_line: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.value);
        hasher.update(raw_event_line);
        self.value.copy_from_slice(&hasher.finalize());
    }

    fn hex(&self) -> String {
        hex_bytes(&self.value)
    }
}

struct EvidenceCapture {
    summary_out: PathBuf,
    summary_workload_id: Option<String>,
    collection_mode: CollectionMode,
    writer: BufWriter<File>,
    digest: RollingDigest,
    event_count: usize,
    observed_lost: u64,
    malformed_samples: usize,
}

impl EvidenceCapture {
    fn new(
        evidence_out: PathBuf,
        workloads: &[WorkloadConfig],
        collection_mode: CollectionMode,
    ) -> Result<Self> {
        Ok(Self {
            summary_out: summary_path_for_evidence(&evidence_out),
            summary_workload_id: workload_summary_id(workloads, collection_mode),
            collection_mode,
            writer: create_evidence_writer(evidence_out)?,
            digest: RollingDigest::new(),
            event_count: 0,
            observed_lost: 0,
            malformed_samples: 0,
        })
    }

    fn process_sample(&mut self, bytes: &[u8], workloads: &[WorkloadConfig]) -> Result<()> {
        if bytes.len() != core::mem::size_of::<Event>() {
            self.malformed_samples += 1;
            warn!(
                "dropping malformed ringbuf sample: got {} bytes, expected {}",
                bytes.len(),
                core::mem::size_of::<Event>()
            );
            return Ok(());
        }

        let ev = bytemuck::pod_read_unaligned::<Event>(bytes);
        let evidence = evidence_event_from_raw(&ev, workloads)?;
        self.observed_lost = self.observed_lost.max(evidence.lost);
        self.write_event(&evidence)?;
        self.event_count += 1;

        println!(
            "{} seq={} lost={} workload={} index={} pid={} comm={} exe_path={}",
            evidence.event_type,
            evidence.seq,
            evidence.lost,
            evidence.workload_id.unwrap_or("<unknown>"),
            evidence.workload_index,
            evidence.pid,
            evidence.comm,
            evidence.exe_path,
        );

        Ok(())
    }

    fn fallback_monitor_state(&self) -> MonitorState {
        MonitorState {
            lock: runtime_monitor_common::BpfSpinLock { val: 0 },
            reserved: 0,
            seq: self.event_count as u64,
            lost: self.observed_lost,
        }
    }

    fn write_summary(&self, final_state: &MonitorState) -> Result<()> {
        let summary = EvidenceSummary {
            workload_id: self.summary_workload_id.as_deref(),
            collection_mode: self.collection_mode.as_str(),
            event_count: self.event_count,
            evidence_digest: self.digest.hex(),
            final_seq: final_state.seq,
            final_lost: final_state.lost,
            malformed_samples: self.malformed_samples,
        };
        summary.write_to(&self.summary_out)
    }

    fn summary_path(&self) -> &Path {
        &self.summary_out
    }

    fn write_event(&mut self, evidence: &EvidenceEvent<'_>) -> Result<()> {
        let line = serde_json::to_vec(evidence)?;
        self.digest.update(&line);
        self.writer.write_all(&line)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TracepointProgram {
    program_name: &'static str,
    category: &'static str,
    tracepoint_name: &'static str,
}

impl TracepointProgram {
    fn attach(&self, ebpf: &mut Ebpf) -> Result<()> {
        let program: &mut TracePoint = ebpf
            .program_mut(self.program_name)
            .ok_or_else(|| anyhow!("program {} not found", self.program_name))?
            .try_into()?;
        program.load()?;
        program.attach(self.category, self.tracepoint_name)?;
        info!(
            "attached tracepoint program: program={} tracepoint={}:{}",
            self.program_name, self.category, self.tracepoint_name
        );
        Ok(())
    }
}

const TRACEPOINT_PROGRAMS: &[TracepointProgram] = &[TracepointProgram {
    program_name: "sched_process_exec",
    category: "sched",
    tracepoint_name: "sched_process_exec",
}];

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn load_collector_config(path: impl AsRef<Path>) -> Result<CollectorConfig> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    let config: CollectorConfig = serde_json::from_reader(file).map_err(|e| {
        anyhow!(
            "failed to parse {} as collector config: {e}",
            path.display()
        )
    })?;
    validate_collector_config(&config)?;
    Ok(config)
}

fn validate_collector_config(config: &CollectorConfig) -> Result<()> {
    let workloads = config.workloads();
    if workloads.is_empty() {
        return Err(anyhow!(
            "collector config must define at least one workload"
        ));
    }
    let _ = config.collection_mode()?;

    let mut workload_ids = HashSet::new();
    let mut container_names = HashSet::new();
    for workload in &workloads {
        if workload.workload_id.trim().is_empty() {
            return Err(anyhow!("collector workload_id must not be empty"));
        }
        if workload.container_name.trim().is_empty() {
            return Err(anyhow!(
                "collector container_name for workload `{}` must not be empty",
                workload.workload_id
            ));
        }
        if !workload_ids.insert(workload.workload_id.as_str()) {
            return Err(anyhow!(
                "duplicate workload_id `{}` in collector config",
                workload.workload_id
            ));
        }
        if !container_names.insert(workload.container_name.as_str()) {
            return Err(anyhow!(
                "duplicate container_name `{}` in collector config",
                workload.container_name
            ));
        }
    }

    Ok(())
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

fn bytes_to_string_len(bytes: &[u8], len: u32) -> Cow<'_, str> {
    let max = usize::min(len as usize, bytes.len());
    bytes_to_string(&bytes[..max])
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
    let mut seen_cgroup_ids = HashSet::new();
    for (workload_index, workload) in workloads.iter().enumerate() {
        let cgroup_id = discover_workload_cgroup_id(workload)?;
        if !seen_cgroup_ids.insert(cgroup_id) {
            return Err(anyhow!(
                "multiple workloads resolved to the same cgroup_id {}; refusing to overwrite TARGET_CGROUPS entry",
                cgroup_id
            ));
        }
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

fn set_collection_mode(ebpf: &mut Ebpf, mode: CollectionMode) -> Result<()> {
    let mut collection_mode: BpfArray<_, u32> = BpfArray::try_from(
        ebpf.map_mut("COLLECTION_MODE")
            .ok_or_else(|| anyhow!("COLLECTION_MODE map not found"))?,
    )?;
    collection_mode.set(0, mode.as_bpf_value(), 0)?;
    Ok(())
}

fn attach_tracepoint_programs(ebpf: &mut Ebpf, programs: &[TracepointProgram]) -> Result<()> {
    for program in programs {
        program.attach(ebpf)?;
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

fn summary_path_for_evidence(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("runtime_events");
    path.with_file_name(format!("{stem}.summary.json"))
}

fn workload_id_for_index(
    workloads: &[WorkloadConfig],
    workload_index: u32,
) -> Result<Option<&str>> {
    if workload_index == UNKNOWN_WORKLOAD_INDEX {
        return Ok(None);
    }

    workloads
        .get(workload_index as usize)
        .map(|workload| Some(workload.workload_id.as_str()))
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
    let exe_path = bytes_to_string_len(&ev.filename, ev.filename_len);
    let filename_read_error = if ev.filename_read_error == 0 {
        None
    } else {
        Some(ev.filename_read_error)
    };

    Ok(EvidenceEvent {
        seq: ev.seq,
        lost: ev.lost,
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

fn workload_summary_id(workloads: &[WorkloadConfig], mode: CollectionMode) -> Option<String> {
    if mode == CollectionMode::HostWide {
        return None;
    }

    if workloads.len() == 1 {
        return Some(workloads[0].workload_id.clone());
    }

    Some(
        workloads
            .iter()
            .map(|workload| workload.workload_id.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn read_monitor_state(ebpf: &Ebpf) -> Result<MonitorState> {
    let state_map = ebpf
        .map("MONITOR_STATE")
        .ok_or_else(|| anyhow!("MONITOR_STATE map not found"))?;
    let state: BpfArray<_, MonitorState> = BpfArray::try_from(state_map)?;
    Ok(state.get(&0, 0)?)
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
    let collection_mode = collector_config.collection_mode()?;
    let evidence_out = PathBuf::from(collector_config.evidence_out()?);
    let mut evidence = EvidenceCapture::new(evidence_out, &workloads, collection_mode)?;

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
    set_collection_mode(&mut ebpf, collection_mode)?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let Ok(mut guard) = logger.readable_mut().await else {
                        break;
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    attach_tracepoint_programs(&mut ebpf, TRACEPOINT_PROGRAMS)?;

    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS map not found"))?,
    )?;

    println!("Listening for events... press Ctrl-C to stop.");

    let ctrl_c = signal::ctrl_c();

    tokio::pin!(ctrl_c);

    loop {
        if let Some(item) = ring.next() {
            evidence.process_sample(&item, &workloads)?;
        } else {
            tokio::select! {
                _ = &mut ctrl_c => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
    }

    while let Some(item) = ring.next() {
        evidence.process_sample(&item, &workloads)?;
    }
    let final_state = read_monitor_state(&ebpf).unwrap_or_else(|e| {
        warn!("failed to read final monitor state for summary: {e}");
        evidence.fallback_monitor_state()
    });
    evidence.write_summary(&final_state)?;
    println!(
        "Wrote evidence summary: {}",
        evidence.summary_path().display()
    );
    Ok(())
}
