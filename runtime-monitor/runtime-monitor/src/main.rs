use anyhow::{Result, anyhow};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array as BpfArray, HashMap, RingBuf},
    programs::TracePoint,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::signal;

use runtime_monitor_common::evidence::{RUNTIME_SUMMARY_SCHEMA_VERSION, RuntimeEvidenceState};
use runtime_monitor_common::{
    COLLECTION_MODE_HOST_WIDE, COLLECTION_MODE_SCOPED, Event, EvidenceRecord,
    EvidenceSyntheticRecord, MonitorState, RuntimeEvent, RuntimePolicy, RuntimeSummary,
    SyntheticRecordType, TargetWorkload, TpmSummary, UNKNOWN_WORKLOAD_INDEX, classify_event,
    event_hash, final_summary_digest, generate_session_id, hex_encode, policy_hash,
    session_start_digest, synthetic_record_hash,
};

mod tpm;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicySource {
    Configured,
    Defaulted,
}

impl PolicySource {
    fn loaded_reason(self) -> &'static str {
        match self {
            Self::Configured => "runtime policy loaded from configured policy",
            Self::Defaulted => "runtime policy defaulted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceCaptureState {
    Open,
    StopWritten,
    Finalized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TpmBindingState {
    initial_pcr: String,
    after_session_start_pcr: String,
    session_start_digest: [u8; 32],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleCollectorConfig {
    workload_id: String,
    container_name: String,
    collection_mode: Option<CollectionMode>,
    evidence_out: String,
    runtime_policy: Option<String>,
    summary_out: Option<String>,
    tpm_tcti: Option<String>,
    #[serde(default)]
    tpm_reset_pcr: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiCollectorConfig {
    workloads: Vec<WorkloadConfig>,
    collection_mode: Option<CollectionMode>,
    evidence_out: Option<String>,
    runtime_policy: Option<String>,
    summary_out: Option<String>,
    tpm_tcti: Option<String>,
    #[serde(default)]
    tpm_reset_pcr: bool,
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

    fn runtime_policy(&self) -> Option<&str> {
        match self {
            Self::Single(config) => config.runtime_policy.as_deref(),
            Self::Multi(config) => config.runtime_policy.as_deref(),
        }
    }

    fn summary_out(&self) -> Option<&str> {
        match self {
            Self::Single(config) => config.summary_out.as_deref(),
            Self::Multi(config) => config.summary_out.as_deref(),
        }
    }

    fn tpm_local_options(&self) -> tpm::TpmLocalOptions {
        match self {
            Self::Single(config) => tpm::TpmLocalOptions {
                tcti: config.tpm_tcti.clone(),
                reset_pcr: config.tpm_reset_pcr,
            },
            Self::Multi(config) => tpm::TpmLocalOptions {
                tcti: config.tpm_tcti.clone(),
                reset_pcr: config.tpm_reset_pcr,
            },
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

struct EvidenceCapture {
    summary_out: PathBuf,
    summary_workload_id: String,
    collection_mode: CollectionMode,
    writer: BufWriter<File>,
    policy: RuntimePolicy,
    policy_hash: [u8; 32],
    policy_hash_hex: String,
    session_id_hex: String,
    state: RuntimeEvidenceState,
    observed_lost: u64,
    malformed_samples: usize,
    capture_state: EvidenceCaptureState,
    tpm_config: tpm::TpmConfig,
    tpm_binding: Option<TpmBindingState>,
    tpm_final_summary: Option<TpmSummary>,
    tpm_failure_reason: Option<String>,
}

impl EvidenceCapture {
    fn new(
        evidence_out: PathBuf,
        summary_out: PathBuf,
        workloads: &[WorkloadConfig],
        collection_mode: CollectionMode,
        policy: RuntimePolicy,
        policy_source: PolicySource,
        tpm_config: tpm::TpmConfig,
    ) -> Result<Self> {
        let session_id = generate_session_id();
        let policy_hash = policy_hash(&policy);
        let policy_hash_hex = hex_encode(&policy_hash);
        let mut capture = Self {
            summary_out,
            summary_workload_id: workload_summary_id(workloads, collection_mode),
            collection_mode,
            writer: create_evidence_writer(evidence_out)?,
            policy,
            policy_hash,
            policy_hash_hex,
            session_id_hex: hex_encode(&session_id),
            state: RuntimeEvidenceState::new(session_id),
            observed_lost: 0,
            malformed_samples: 0,
            capture_state: EvidenceCaptureState::Open,
            tpm_config,
            tpm_binding: None,
            tpm_final_summary: None,
            tpm_failure_reason: None,
        };
        capture
            .write_synthetic_record(SyntheticRecordType::MonitorStart, "monitor session started")?;
        capture.write_synthetic_record(
            SyntheticRecordType::PolicyLoaded,
            policy_source.loaded_reason(),
        )?;
        Ok(capture)
    }

    fn process_sample(&mut self, bytes: &[u8], workloads: &[WorkloadConfig]) -> Result<()> {
        self.ensure_open("process runtime sample")?;

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
        self.observed_lost = self.observed_lost.max(ev.lost);
        let workload_id = workload_id_for_index(workloads, ev.workload_index)?.map(str::to_owned);
        let runtime_event = RuntimeEvent::from_raw_event(&ev, workload_id);
        let seq_no = self.state.advance_sequence();
        let classification = classify_event(&runtime_event, &self.policy);
        let event_hash_bytes = event_hash(&self.state.session_id, seq_no, &runtime_event);
        let software_chain_head = self.state.update_chain(event_hash_bytes);
        self.state
            .observe_classification(classification.classification);

        let evidence = runtime_monitor_common::EvidenceEvent {
            session_id: self.session_id_hex.clone(),
            seq_no,
            event: runtime_event,
            classification: classification.classification,
            rule_id: classification.rule_id,
            reason: classification.reason,
            event_hash: hex_encode(&event_hash_bytes),
            software_chain_head: hex_encode(&software_chain_head),
            tpm_extended: false,
            tpm_extend_index: None,
        };
        self.write_record(&EvidenceRecord::RuntimeEvent(evidence.clone()))?;

        println!(
            "{:?} seq={} workload={} index={} pid={} comm={} exe_path={} classification={:?}",
            evidence.event.event_type,
            evidence.seq_no,
            evidence.event.workload_id.as_deref().unwrap_or("<unknown>"),
            evidence.event.workload_index,
            evidence.event.pid,
            evidence.event.comm,
            evidence.event.exe_path,
            evidence.classification,
        );

        Ok(())
    }

    fn fallback_monitor_state(&self) -> MonitorState {
        MonitorState {
            seq: self.state.event_count,
            lost: self.observed_lost,
        }
    }

    fn bind_tpm_session_start<R>(&mut self, runner: &R) -> Result<()>
    where
        R: tpm::TpmCommandRunner,
    {
        self.ensure_open("bind TPM session start")?;

        if !self.tpm_config.enabled || self.tpm_failure_reason.is_some() {
            return Ok(());
        }

        let result = (|| -> Result<TpmBindingState> {
            if self.tpm_config.reset_pcr {
                tpm::pcr_reset(runner, &self.tpm_config)?;
            }

            let initial_pcr = tpm::pcr_read(runner, &self.tpm_config)?.digest_hex;
            let session_digest = session_start_digest(
                &self.state.session_id,
                self.policy_hash,
                &self.summary_workload_id,
                self.collection_mode.as_str(),
            );
            tpm::pcr_extend(runner, &self.tpm_config, &hex_encode(&session_digest))?;
            let after_session_start_pcr = tpm::pcr_read(runner, &self.tpm_config)?.digest_hex;

            Ok(TpmBindingState {
                initial_pcr,
                after_session_start_pcr,
                session_start_digest: session_digest,
            })
        })();

        match result {
            Ok(binding) => {
                self.tpm_binding = Some(binding);
                Ok(())
            }
            Err(error) => self.record_tpm_failure("TPM session-start binding failed", error),
        }
    }

    fn write_summary<R>(&mut self, final_state: &MonitorState, runner: &R) -> Result<()>
    where
        R: tpm::TpmCommandRunner,
    {
        match self.capture_state {
            EvidenceCaptureState::Open => {
                self.write_synthetic_record(
                    SyntheticRecordType::MonitorStop,
                    "monitor session stopped",
                )?;
                self.writer.flush()?;
                self.capture_state = EvidenceCaptureState::StopWritten;
            }
            EvidenceCaptureState::StopWritten => {}
            EvidenceCaptureState::Finalized => {
                return Err(anyhow!(
                    "cannot write runtime summary: evidence capture is already finalized"
                ));
            }
        }

        if final_state.lost > 0 {
            warn!(
                "observed final eBPF lost-event counter {}; runtime summary records it, but precise drop semantics still need validation",
                final_state.lost
            );
        }

        let final_digest = final_summary_digest(
            &self.state.session_id,
            self.state.software_chain_head,
            self.state.event_count,
            self.state.synthetic_record_count,
            self.state.acceptable_count,
            self.state.suspicious_count,
            self.state.denied_count,
            final_state.lost,
            self.policy_hash,
        );
        let tpm_summary = self.finalize_tpm_binding(runner, final_digest)?;
        let (attestation_status, failure_reason) = self.summary_attestation_status_and_reason();
        let final_summary_digest = tpm_summary
            .as_ref()
            .map(|summary| summary.final_summary_digest.clone());
        let summary = RuntimeSummary {
            schema_version: RUNTIME_SUMMARY_SCHEMA_VERSION,
            session_id: self.session_id_hex.clone(),
            workload_id: self.summary_workload_id.clone(),
            collection_mode: self.collection_mode.as_str().to_owned(),
            policy_hash: self.policy_hash_hex.clone(),
            monitor_config_hash: None,
            attestation_status: attestation_status.to_owned(),
            failure_reason,
            event_count: self.state.event_count,
            synthetic_record_count: self.state.synthetic_record_count,
            acceptable_count: self.state.acceptable_count,
            suspicious_count: self.state.suspicious_count,
            denied_count: self.state.denied_count,
            // TODO: validate and wire precise eBPF/ring-buffer drop semantics before making strong completeness claims.
            dropped_events: final_state.lost,
            software_chain_head: hex_encode(&self.state.software_chain_head),
            final_summary_digest,
            tpm: tpm_summary,
        };
        write_runtime_summary(&summary, &self.summary_out)?;
        self.capture_state = EvidenceCaptureState::Finalized;
        Ok(())
    }

    fn summary_path(&self) -> &Path {
        &self.summary_out
    }

    fn write_workload_target_bound(&mut self, workloads: &[WorkloadConfig]) -> Result<()> {
        self.ensure_open("write workload-target-bound lifecycle record")?;

        let reason = format!(
            "workload targets bound: collection_mode={} workloads={}",
            self.collection_mode.as_str(),
            workload_summary_id(workloads, self.collection_mode)
        );
        self.write_synthetic_record(SyntheticRecordType::WorkloadTargetBound, &reason)
    }

    fn write_synthetic_record(
        &mut self,
        record_type: SyntheticRecordType,
        reason: &str,
    ) -> Result<()> {
        self.ensure_open("write synthetic lifecycle record")?;

        let seq_no = self.state.advance_sequence();
        let record_hash =
            synthetic_record_hash(&self.state.session_id, seq_no, record_type, reason);
        let software_chain_head = self.state.update_chain(record_hash);
        self.state.observe_synthetic_record();

        let record = EvidenceSyntheticRecord {
            session_id: self.session_id_hex.clone(),
            seq_no,
            record_type,
            reason: reason.to_owned(),
            record_hash: hex_encode(&record_hash),
            software_chain_head: hex_encode(&software_chain_head),
        };
        self.write_record(&EvidenceRecord::Synthetic(record))
    }

    fn finalize_tpm_binding<R>(
        &mut self,
        runner: &R,
        final_digest: [u8; 32],
    ) -> Result<Option<TpmSummary>>
    where
        R: tpm::TpmCommandRunner,
    {
        if !self.tpm_config.enabled || self.tpm_failure_reason.is_some() {
            return Ok(None);
        }

        if let Some(summary) = self.tpm_final_summary.clone() {
            if summary.final_summary_digest != hex_encode(&final_digest) {
                return Err(anyhow!(
                    "cannot write runtime summary: cached TPM final-summary digest {} does not match current digest {}",
                    summary.final_summary_digest,
                    hex_encode(&final_digest)
                ));
            }
            return Ok(Some(summary));
        }

        let Some(binding) = self.tpm_binding.clone() else {
            let error =
                anyhow!("TPM session-start binding was not completed before final summary binding");
            self.record_tpm_failure("TPM final-summary binding failed", error)?;
            return Ok(None);
        };

        let result = (|| -> Result<TpmSummary> {
            tpm::pcr_extend(runner, &self.tpm_config, &hex_encode(&final_digest))?;
            let final_pcr = tpm::pcr_read(runner, &self.tpm_config)?.digest_hex;
            let runtime_pcr = self
                .tpm_config
                .runtime_pcr
                .ok_or_else(|| anyhow!("TPM runtime PCR is not configured"))?;

            Ok(TpmSummary {
                enabled: true,
                hash_bank: self.tpm_config.hash_bank.clone(),
                runtime_pcr,
                reset_pcr: self.tpm_config.reset_pcr,
                initial_pcr: Some(binding.initial_pcr),
                after_session_start_pcr: Some(binding.after_session_start_pcr),
                final_pcr: Some(final_pcr),
                session_start_digest: hex_encode(&binding.session_start_digest),
                final_summary_digest: hex_encode(&final_digest),
            })
        })();

        match result {
            Ok(summary) => {
                self.tpm_final_summary = Some(summary.clone());
                Ok(Some(summary))
            }
            Err(error) => {
                self.record_tpm_failure("TPM final-summary binding failed", error)?;
                Ok(None)
            }
        }
    }

    fn record_tpm_failure(&mut self, context: &str, error: anyhow::Error) -> Result<()> {
        let reason = format!("{context}: {error}");
        if self.tpm_config.fail_on_tpm_error {
            return Err(anyhow!(reason));
        }

        warn!("TPM binding failed open: {reason}");
        self.tpm_failure_reason.get_or_insert(reason);
        Ok(())
    }

    fn summary_attestation_status_and_reason(&self) -> (String, Option<String>) {
        let (status, reason) = attestation_status_and_reason(&self.state, &self.policy);
        let Some(tpm_failure_reason) = self.tpm_failure_reason.as_deref() else {
            return (status.to_owned(), reason);
        };

        let tpm_reason = format!("TPM binding failed open: {tpm_failure_reason}");
        let status = if status == "passed" {
            "warning"
        } else {
            status
        };
        let reason = match reason {
            Some(reason) => Some(format!("{reason}; {tpm_reason}")),
            None => Some(tpm_reason),
        };

        (status.to_owned(), reason)
    }

    fn ensure_open(&self, operation: &str) -> Result<()> {
        if self.capture_state != EvidenceCaptureState::Open {
            return Err(anyhow!(
                "cannot {operation}: evidence capture is no longer open"
            ));
        }
        Ok(())
    }

    fn write_record(&mut self, evidence: &EvidenceRecord) -> Result<()> {
        let line = serde_json::to_vec(evidence)?;
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

fn load_runtime_policy(path: impl AsRef<Path>) -> Result<RuntimePolicy> {
    let path = path.as_ref();
    let file = File::open(path)
        .map_err(|e| anyhow!("failed to open runtime policy {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse runtime policy {}: {e}", path.display()))
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

fn log_tpm_config(config: &tpm::TpmConfig) {
    if !config.enabled {
        info!("TPM backend disabled");
        return;
    }

    let runtime_pcr = config
        .runtime_pcr
        .map(|pcr| pcr.to_string())
        .unwrap_or_else(|| String::from("<none>"));
    let tcti = config.tcti.as_deref().unwrap_or("<default>");
    info!(
        "TPM backend configured: hash_bank={} runtime_pcr={} reset_pcr={} tcti={} fail_on_tpm_error={}",
        config.hash_bank, runtime_pcr, config.reset_pcr, tcti, config.fail_on_tpm_error
    );
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

fn default_summary_path_for_evidence(path: &Path) -> PathBuf {
    path.with_file_name("runtime_summary.json")
}

fn write_runtime_summary(summary: &RuntimeSummary, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "failed to create runtime summary directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let file = File::create(path)
        .map_err(|e| anyhow!("failed to create runtime summary {}: {e}", path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(file), summary)
        .map_err(|e| anyhow!("failed to write runtime summary {}: {e}", path.display()))
}

fn attestation_status_and_reason(
    state: &RuntimeEvidenceState,
    policy: &RuntimePolicy,
) -> (&'static str, Option<String>) {
    if state.denied_count > 0 && policy.attestation.fail_on_denied {
        return (
            "failed",
            Some(String::from("denied runtime behaviour observed")),
        );
    }

    if state.suspicious_count > 0 && policy.attestation.fail_on_suspicious {
        return (
            "failed",
            Some(String::from("suspicious runtime behaviour observed")),
        );
    }

    if state.suspicious_count > 0 || state.denied_count > 0 {
        return ("warning", None);
    }

    ("passed", None)
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

fn workload_summary_id(workloads: &[WorkloadConfig], mode: CollectionMode) -> String {
    if mode == CollectionMode::HostWide {
        return String::from("host-wide");
    }

    if workloads.len() == 1 {
        return workloads[0].workload_id.clone();
    }

    workloads
        .iter()
        .map(|workload| workload.workload_id.as_str())
        .collect::<Vec<_>>()
        .join(",")
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
    let summary_out = collector_config
        .summary_out()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_summary_path_for_evidence(&evidence_out));
    let (runtime_policy, policy_source) = if let Some(path) = collector_config.runtime_policy() {
        (load_runtime_policy(path)?, PolicySource::Configured)
    } else {
        warn!(
            "no runtime_policy configured; using RuntimePolicy::default(), which may classify most events as suspicious"
        );
        (RuntimePolicy::default(), PolicySource::Defaulted)
    };
    let tpm_config = tpm::TpmConfig::from_policy_and_local_options(
        &runtime_policy.attestation,
        collector_config.tpm_local_options(),
    )?;
    log_tpm_config(&tpm_config);
    let tpm_runner = tpm::SystemTpmCommandRunner;
    let mut evidence = EvidenceCapture::new(
        evidence_out,
        summary_out,
        &workloads,
        collection_mode,
        runtime_policy,
        policy_source,
        tpm_config,
    )?;

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
    evidence.write_workload_target_bound(&workloads)?;
    evidence.bind_tpm_session_start(&tpm_runner)?;

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
    evidence.write_summary(&final_state, &tpm_runner)?;
    println!(
        "Wrote evidence summary: {}",
        evidence.summary_path().display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_monitor_common::{
        AttestationPolicy, EventClassification, EventType, EvidenceRecord, PATH_LEN,
        SyntheticRecordType, TASK_COMM_LEN,
    };
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    struct NoopTpmRunner;

    impl tpm::TpmCommandRunner for NoopTpmRunner {
        fn run(&self, program: &str, _args: &[String], _envs: &[(&str, &str)]) -> Result<Output> {
            Err(anyhow!(
                "unexpected TPM command in TPM-disabled test: {program}"
            ))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockTpmCall {
        program: String,
        args: Vec<String>,
    }

    struct MockTpmRunner {
        calls: RefCell<Vec<MockTpmCall>>,
        pcr: RefCell<[u8; 32]>,
        fail_program: Option<&'static str>,
    }

    impl MockTpmRunner {
        fn new(initial_pcr: [u8; 32]) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                pcr: RefCell::new(initial_pcr),
                fail_program: None,
            }
        }

        fn failing(program: &'static str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                pcr: RefCell::new([0u8; 32]),
                fail_program: Some(program),
            }
        }

        fn calls(&self) -> Vec<MockTpmCall> {
            self.calls.borrow().clone()
        }
    }

    impl tpm::TpmCommandRunner for MockTpmRunner {
        fn run(&self, program: &str, args: &[String], _envs: &[(&str, &str)]) -> Result<Output> {
            self.calls.borrow_mut().push(MockTpmCall {
                program: program.to_owned(),
                args: args.to_vec(),
            });

            if self
                .fail_program
                .is_some_and(|candidate| candidate == program)
            {
                return Ok(Output {
                    status: ExitStatus::from_raw(1),
                    stdout: Vec::new(),
                    stderr: b"mock TPM failure".to_vec(),
                });
            }

            let stdout = match program {
                "tpm2_pcrread" => {
                    let digest = hex_encode(&*self.pcr.borrow());
                    format!("sha256:\n  23: 0x{digest}\n").into_bytes()
                }
                "tpm2_pcrreset" => {
                    *self.pcr.borrow_mut() = [0u8; 32];
                    Vec::new()
                }
                "tpm2_pcrextend" => {
                    let digest_hex = args
                        .first()
                        .and_then(|arg| arg.split_once('=').map(|(_, digest)| digest))
                        .ok_or_else(|| anyhow!("mock TPM extend missing digest argument"))?;
                    let digest = runtime_monitor_common::hex_decode_32(digest_hex)?;
                    let current = *self.pcr.borrow();
                    *self.pcr.borrow_mut() =
                        runtime_monitor_common::replay_pcr_extend(current, digest);
                    Vec::new()
                }
                _ => Vec::new(),
            };

            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout,
                stderr: Vec::new(),
            })
        }
    }

    fn disabled_tpm_config() -> tpm::TpmConfig {
        tpm::TpmConfig::from_policy_and_local_options(
            &AttestationPolicy::default(),
            tpm::TpmLocalOptions::default(),
        )
        .expect("disabled tpm config")
    }

    fn tpm_runtime_policy(fail_on_tpm_error: bool) -> RuntimePolicy {
        RuntimePolicy {
            attestation: AttestationPolicy {
                backend: String::from("tpm"),
                mode: String::from("final-summary"),
                runtime_pcr: Some(23),
                hash_bank: Some(String::from("sha256")),
                fail_on_tpm_error: Some(fail_on_tpm_error),
                ..AttestationPolicy::default()
            },
            ..RuntimePolicy::default()
        }
    }

    fn enabled_tpm_config(policy: &RuntimePolicy, reset_pcr: bool) -> tpm::TpmConfig {
        tpm::TpmConfig::from_policy_and_local_options(
            &policy.attestation,
            tpm::TpmLocalOptions {
                reset_pcr,
                ..tpm::TpmLocalOptions::default()
            },
        )
        .expect("enabled tpm config")
    }

    fn state_with_counts(suspicious_count: u64, denied_count: u64) -> RuntimeEvidenceState {
        let mut state = RuntimeEvidenceState::new([1u8; 32]);
        for _ in 0..suspicious_count {
            state.observe_classification(EventClassification::Suspicious);
        }
        for _ in 0..denied_count {
            state.observe_classification(EventClassification::Denied);
        }
        state
    }

    #[test]
    fn attestation_status_passes_without_suspicious_or_denied_events() {
        let state = state_with_counts(0, 0);
        let policy = RuntimePolicy::default();

        let (status, reason) = attestation_status_and_reason(&state, &policy);

        assert_eq!(status, "passed");
        assert!(reason.is_none());
    }

    #[test]
    fn attestation_status_warns_for_non_failing_suspicious_events() {
        let state = state_with_counts(1, 0);
        let mut policy = RuntimePolicy::default();
        policy.attestation.fail_on_suspicious = false;

        let (status, reason) = attestation_status_and_reason(&state, &policy);

        assert_eq!(status, "warning");
        assert!(reason.is_none());
    }

    #[test]
    fn attestation_status_fails_for_policy_failing_suspicious_events() {
        let state = state_with_counts(1, 0);
        let mut policy = RuntimePolicy::default();
        policy.attestation.fail_on_suspicious = true;

        let (status, reason) = attestation_status_and_reason(&state, &policy);

        assert_eq!(status, "failed");
        assert_eq!(
            reason.as_deref(),
            Some("suspicious runtime behaviour observed")
        );
    }

    #[test]
    fn attestation_status_fails_for_policy_failing_denied_events() {
        let state = state_with_counts(0, 1);
        let mut policy = RuntimePolicy::default();
        policy.attestation.fail_on_denied = true;

        let (status, reason) = attestation_status_and_reason(&state, &policy);

        assert_eq!(status, "failed");
        assert_eq!(reason.as_deref(), Some("denied runtime behaviour observed"));
    }

    #[test]
    fn default_summary_path_is_runtime_summary_next_to_evidence() {
        let path = default_summary_path_for_evidence(Path::new("logs/runtime_events.jsonl"));

        assert_eq!(path, PathBuf::from("logs/runtime_summary.json"));
    }

    #[test]
    fn collector_config_parses_local_tpm_options() {
        let config = serde_json::from_str::<CollectorConfig>(
            r#"{
                "workload_id": "workload-a",
                "container_name": "container-a",
                "collection_mode": "scoped",
                "evidence_out": "logs/runtime_events.jsonl",
                "tpm_tcti": "swtpm:host=localhost,port=2321",
                "tpm_reset_pcr": true
            }"#,
        )
        .expect("collector config");

        let options = config.tpm_local_options();

        assert_eq!(
            options.tcti.as_deref(),
            Some("swtpm:host=localhost,port=2321")
        );
        assert!(options.reset_pcr);
    }

    fn temp_output_paths(test_name: &str) -> (PathBuf, PathBuf) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "runtime-monitor-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        (
            dir.join("runtime_events.jsonl"),
            dir.join("runtime_summary.json"),
        )
    }

    fn test_workloads() -> Vec<WorkloadConfig> {
        vec![WorkloadConfig {
            workload_id: String::from("workload-a"),
            container_name: String::from("container-a"),
        }]
    }

    fn read_evidence_records(path: &Path) -> Vec<EvidenceRecord> {
        fs::read_to_string(path)
            .expect("evidence jsonl")
            .lines()
            .map(|line| serde_json::from_str::<EvidenceRecord>(line).expect("record"))
            .collect::<Vec<_>>()
    }

    fn record_seq_no(record: &EvidenceRecord) -> u64 {
        match record {
            EvidenceRecord::Synthetic(record) => record.seq_no,
            EvidenceRecord::RuntimeEvent(event) => event.seq_no,
        }
    }

    fn sample_raw_event(exe_path: &str) -> Event {
        let mut event = Event {
            seq: 1,
            lost: 0,
            ts_ns: 42,
            cgroup_id: 99,
            event_type: EventType::Exec as u32,
            pid: 123,
            tgid: 123,
            ppid: 1,
            cpu: 2,
            workload_index: 0,
            workload_flags: 0,
            filename_len: 0,
            filename_flags: 0,
            filename_read_error: 0,
            reserved: 0,
            reserved2: 0,
            comm: [0; TASK_COMM_LEN],
            filename: [0; PATH_LEN],
        };

        let comm = b"echo";
        event.comm[..comm.len()].copy_from_slice(comm);

        let filename = exe_path.as_bytes();
        assert!(filename.len() <= PATH_LEN);
        event.filename[..filename.len()].copy_from_slice(filename);
        event.filename_len = filename.len() as u32;

        event
    }

    #[test]
    fn lifecycle_records_increment_synthetic_count_and_update_chain() {
        let (evidence_out, summary_out) = temp_output_paths("lifecycle");
        let workloads = test_workloads();
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            RuntimePolicy::default(),
            PolicySource::Configured,
            disabled_tpm_config(),
        )
        .expect("evidence capture");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner)
            .expect("summary");

        assert_eq!(evidence.capture_state, EvidenceCaptureState::Finalized);

        let records = read_evidence_records(&evidence_out);
        let seq_nos = records.iter().map(record_seq_no).collect::<Vec<_>>();
        let record_types = records
            .iter()
            .map(|record| match record {
                EvidenceRecord::Synthetic(record) => record.record_type,
                EvidenceRecord::RuntimeEvent(_) => panic!("expected synthetic record"),
            })
            .collect::<Vec<_>>();

        assert_eq!(seq_nos, vec![1, 2, 3, 4]);
        assert_eq!(
            record_types,
            vec![
                SyntheticRecordType::MonitorStart,
                SyntheticRecordType::PolicyLoaded,
                SyntheticRecordType::WorkloadTargetBound,
                SyntheticRecordType::MonitorStop,
            ]
        );

        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");
        let final_chain_head = match records.last().expect("monitor-stop") {
            EvidenceRecord::Synthetic(record) => record.software_chain_head.clone(),
            EvidenceRecord::RuntimeEvent(_) => panic!("expected final synthetic record"),
        };

        assert_eq!(summary.event_count, 0);
        assert_eq!(summary.synthetic_record_count, 4);
        assert_eq!(summary.software_chain_head, final_chain_head);
        assert!(summary.tpm.is_none());
        assert!(summary.final_summary_digest.is_none());

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn runtime_sample_uses_contiguous_lifecycle_sequence_and_summary_chain() {
        let (evidence_out, summary_out) = temp_output_paths("runtime-sequence");
        let workloads = test_workloads();
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            RuntimePolicy::default(),
            PolicySource::Configured,
            disabled_tpm_config(),
        )
        .expect("evidence capture");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        let event = sample_raw_event("/usr/bin/echo");
        evidence
            .process_sample(bytemuck::bytes_of(&event), &workloads)
            .expect("runtime sample");
        evidence
            .write_summary(&MonitorState { seq: 1, lost: 0 }, &NoopTpmRunner)
            .expect("summary");

        let records = read_evidence_records(&evidence_out);
        let seq_nos = records.iter().map(record_seq_no).collect::<Vec<_>>();
        assert_eq!(seq_nos, vec![1, 2, 3, 4, 5]);

        let EvidenceRecord::Synthetic(start) = &records[0] else {
            panic!("expected monitor-start");
        };
        let EvidenceRecord::Synthetic(policy_loaded) = &records[1] else {
            panic!("expected policy-loaded");
        };
        let EvidenceRecord::Synthetic(target_bound) = &records[2] else {
            panic!("expected workload-target-bound");
        };
        let EvidenceRecord::RuntimeEvent(runtime_event) = &records[3] else {
            panic!("expected runtime event");
        };
        let EvidenceRecord::Synthetic(stop) = &records[4] else {
            panic!("expected monitor-stop");
        };

        assert_eq!(start.record_type, SyntheticRecordType::MonitorStart);
        assert_eq!(policy_loaded.record_type, SyntheticRecordType::PolicyLoaded);
        assert_eq!(
            target_bound.record_type,
            SyntheticRecordType::WorkloadTargetBound
        );
        assert_eq!(runtime_event.event.exe_path, "/usr/bin/echo");
        assert_eq!(stop.record_type, SyntheticRecordType::MonitorStop);

        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");

        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.synthetic_record_count, 4);
        assert_eq!(summary.software_chain_head, stop.software_chain_head);

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn finalized_capture_rejects_later_writes_without_appending_records() {
        let (evidence_out, summary_out) = temp_output_paths("finalized-guard");
        let workloads = test_workloads();
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            RuntimePolicy::default(),
            PolicySource::Configured,
            disabled_tpm_config(),
        )
        .expect("evidence capture");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner)
            .expect("summary");
        assert_eq!(evidence.capture_state, EvidenceCaptureState::Finalized);

        let records_after_summary = read_evidence_records(&evidence_out);
        assert_eq!(records_after_summary.len(), 4);

        let second_summary =
            evidence.write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner);
        assert!(second_summary.is_err());
        assert_eq!(read_evidence_records(&evidence_out).len(), 4);

        let target_bound_after_finalize = evidence.write_workload_target_bound(&workloads);
        assert!(target_bound_after_finalize.is_err());
        assert_eq!(read_evidence_records(&evidence_out).len(), 4);

        let event = sample_raw_event("/usr/bin/echo");
        let sample_after_finalize = evidence.process_sample(bytemuck::bytes_of(&event), &workloads);
        assert!(sample_after_finalize.is_err());

        let final_records = read_evidence_records(&evidence_out);
        let stop_count = final_records
            .iter()
            .filter(|record| {
                matches!(
                    record,
                    EvidenceRecord::Synthetic(record)
                        if record.record_type == SyntheticRecordType::MonitorStop
                )
            })
            .count();
        assert_eq!(final_records.len(), 4);
        assert_eq!(stop_count, 1);

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn summary_write_retry_after_monitor_stop_does_not_append_stop_twice() {
        let (evidence_out, summary_out) = temp_output_paths("summary-retry");
        let bad_summary_out = evidence_out.join("runtime_summary.json");
        let workloads = test_workloads();
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            bad_summary_out,
            &workloads,
            CollectionMode::Scoped,
            RuntimePolicy::default(),
            PolicySource::Configured,
            disabled_tpm_config(),
        )
        .expect("evidence capture");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        let failed_summary =
            evidence.write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner);
        assert!(failed_summary.is_err());
        assert_eq!(evidence.capture_state, EvidenceCaptureState::StopWritten);

        let records_after_failure = read_evidence_records(&evidence_out);
        assert_eq!(records_after_failure.len(), 4);

        evidence.summary_out = summary_out.clone();
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner)
            .expect("summary retry");
        assert_eq!(evidence.capture_state, EvidenceCaptureState::Finalized);

        let final_records = read_evidence_records(&evidence_out);
        let stop_records = final_records
            .iter()
            .filter(|record| {
                matches!(
                    record,
                    EvidenceRecord::Synthetic(record)
                        if record.record_type == SyntheticRecordType::MonitorStop
                )
            })
            .count();
        let EvidenceRecord::Synthetic(stop) = final_records.last().expect("monitor-stop") else {
            panic!("expected final monitor-stop");
        };
        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");

        assert_eq!(final_records.len(), 4);
        assert_eq!(stop_records, 1);
        assert_eq!(summary.synthetic_record_count, 4);
        assert_eq!(summary.software_chain_head, stop.software_chain_head);

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn summary_write_retry_after_final_tpm_extend_reuses_cached_tpm_summary() {
        let (evidence_out, summary_out) = temp_output_paths("tpm-summary-retry");
        let bad_summary_out = evidence_out.join("runtime_summary.json");
        let workloads = test_workloads();
        let policy = tpm_runtime_policy(true);
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            bad_summary_out,
            &workloads,
            CollectionMode::Scoped,
            policy.clone(),
            PolicySource::Configured,
            enabled_tpm_config(&policy, true),
        )
        .expect("evidence capture");
        let runner = MockTpmRunner::new([0u8; 32]);

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        evidence
            .bind_tpm_session_start(&runner)
            .expect("session-start binding");

        let failed_summary = evidence.write_summary(&MonitorState { seq: 0, lost: 0 }, &runner);
        assert!(failed_summary.is_err());
        assert_eq!(evidence.capture_state, EvidenceCaptureState::StopWritten);
        let cached_tpm_summary = evidence
            .tpm_final_summary
            .clone()
            .expect("cached final TPM metadata");
        let extend_calls_after_failure = runner
            .calls()
            .iter()
            .filter(|call| call.program == "tpm2_pcrextend")
            .count();
        assert_eq!(extend_calls_after_failure, 2);

        evidence.summary_out = summary_out.clone();
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &runner)
            .expect("summary retry");

        let extend_calls_after_retry = runner
            .calls()
            .iter()
            .filter(|call| call.program == "tpm2_pcrextend")
            .count();
        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");

        assert_eq!(extend_calls_after_retry, 2);
        assert_eq!(summary.tpm.as_ref(), Some(&cached_tpm_summary));
        assert_eq!(
            summary.final_summary_digest.as_deref(),
            Some(cached_tpm_summary.final_summary_digest.as_str())
        );

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn tpm_enabled_binds_session_and_final_summary_with_mock_runner() {
        let (evidence_out, summary_out) = temp_output_paths("tpm-enabled");
        let workloads = test_workloads();
        let policy = tpm_runtime_policy(true);
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            policy.clone(),
            PolicySource::Configured,
            enabled_tpm_config(&policy, true),
        )
        .expect("evidence capture");
        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");

        let initial_pcr = [0u8; 32];
        let session_digest = session_start_digest(
            &evidence.state.session_id,
            evidence.policy_hash,
            &evidence.summary_workload_id,
            evidence.collection_mode.as_str(),
        );
        let after_session_start_pcr =
            runtime_monitor_common::replay_pcr_extend(initial_pcr, session_digest);
        let runner = MockTpmRunner::new(initial_pcr);

        evidence
            .bind_tpm_session_start(&runner)
            .expect("session-start binding");
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &runner)
            .expect("summary");

        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");
        let records = read_evidence_records(&evidence_out);
        let EvidenceRecord::Synthetic(stop) = records.last().expect("monitor-stop") else {
            panic!("expected monitor-stop");
        };
        let summary_chain_head =
            runtime_monitor_common::hex_decode_32(&summary.software_chain_head).expect("chain");
        let expected_final_digest = final_summary_digest(
            &evidence.state.session_id,
            summary_chain_head,
            summary.event_count,
            summary.synthetic_record_count,
            summary.acceptable_count,
            summary.suspicious_count,
            summary.denied_count,
            summary.dropped_events,
            policy_hash(&policy),
        );
        let expected_final_pcr = runtime_monitor_common::replay_pcr_extend(
            after_session_start_pcr,
            expected_final_digest,
        );
        let tpm_summary = summary.tpm.as_ref().expect("tpm summary");

        assert_eq!(summary.software_chain_head, stop.software_chain_head);
        assert_eq!(
            summary.final_summary_digest.as_deref(),
            Some(hex_encode(&expected_final_digest).as_str())
        );
        assert_eq!(
            tpm_summary.initial_pcr.as_deref(),
            Some(hex_encode(&initial_pcr).as_str())
        );
        assert_eq!(
            tpm_summary.after_session_start_pcr.as_deref(),
            Some(hex_encode(&after_session_start_pcr).as_str())
        );
        assert_eq!(
            tpm_summary.final_pcr.as_deref(),
            Some(hex_encode(&expected_final_pcr).as_str())
        );
        assert_eq!(
            tpm_summary.session_start_digest,
            hex_encode(&session_digest)
        );
        assert_eq!(
            tpm_summary.final_summary_digest,
            hex_encode(&expected_final_digest)
        );
        assert_eq!(tpm_summary.reset_pcr, true);

        assert_eq!(
            runner.calls(),
            vec![
                MockTpmCall {
                    program: String::from("tpm2_pcrreset"),
                    args: vec![String::from("23")]
                },
                MockTpmCall {
                    program: String::from("tpm2_pcrread"),
                    args: vec![String::from("sha256:23")]
                },
                MockTpmCall {
                    program: String::from("tpm2_pcrextend"),
                    args: vec![format!("23:sha256={}", hex_encode(&session_digest))]
                },
                MockTpmCall {
                    program: String::from("tpm2_pcrread"),
                    args: vec![String::from("sha256:23")]
                },
                MockTpmCall {
                    program: String::from("tpm2_pcrextend"),
                    args: vec![format!("23:sha256={}", hex_encode(&expected_final_digest))]
                },
                MockTpmCall {
                    program: String::from("tpm2_pcrread"),
                    args: vec![String::from("sha256:23")]
                },
            ]
        );

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn tpm_failure_fails_closed_when_policy_requires_it() {
        let (evidence_out, summary_out) = temp_output_paths("tpm-fail-closed");
        let workloads = test_workloads();
        let policy = tpm_runtime_policy(true);
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            policy.clone(),
            PolicySource::Configured,
            enabled_tpm_config(&policy, false),
        )
        .expect("evidence capture");
        let runner = MockTpmRunner::failing("tpm2_pcrread");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        let error = evidence
            .bind_tpm_session_start(&runner)
            .expect_err("TPM failure should fail closed");

        assert!(
            error
                .to_string()
                .contains("TPM session-start binding failed")
        );

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn tpm_failure_can_fail_open_without_success_metadata() {
        let (evidence_out, summary_out) = temp_output_paths("tpm-fail-open");
        let workloads = test_workloads();
        let policy = tpm_runtime_policy(false);
        let mut evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            policy.clone(),
            PolicySource::Configured,
            enabled_tpm_config(&policy, false),
        )
        .expect("evidence capture");
        let runner = MockTpmRunner::failing("tpm2_pcrread");

        evidence
            .write_workload_target_bound(&workloads)
            .expect("target bound");
        evidence
            .bind_tpm_session_start(&runner)
            .expect("TPM failure should fail open");
        evidence
            .write_summary(&MonitorState { seq: 0, lost: 0 }, &NoopTpmRunner)
            .expect("summary");

        let summary = serde_json::from_str::<RuntimeSummary>(
            &fs::read_to_string(&summary_out).expect("summary"),
        )
        .expect("runtime summary");

        assert_eq!(summary.attestation_status, "warning");
        assert!(
            summary
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("TPM binding failed open"))
        );
        assert!(summary.tpm.is_none());
        assert!(summary.final_summary_digest.is_none());

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }

    #[test]
    fn policy_loaded_reason_records_policy_source() {
        let (evidence_out, summary_out) = temp_output_paths("policy-source");
        let workloads = test_workloads();
        let _evidence = EvidenceCapture::new(
            evidence_out.clone(),
            summary_out.clone(),
            &workloads,
            CollectionMode::Scoped,
            RuntimePolicy::default(),
            PolicySource::Defaulted,
            disabled_tpm_config(),
        )
        .expect("evidence capture");

        let records = read_evidence_records(&evidence_out);
        let EvidenceRecord::Synthetic(policy_loaded) = &records[1] else {
            panic!("expected policy-loaded");
        };

        assert_eq!(policy_loaded.record_type, SyntheticRecordType::PolicyLoaded);
        assert_eq!(policy_loaded.reason, "runtime policy defaulted");

        let _ = fs::remove_file(evidence_out);
        let _ = fs::remove_file(summary_out);
    }
}
