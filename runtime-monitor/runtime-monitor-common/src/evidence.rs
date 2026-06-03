use crate::{Event, EventType, UNKNOWN_WORKLOAD_INDEX};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::format;
use std::fs::File;
use std::io::Read;
use std::string::String;
use std::vec::Vec;

const EVENT_DOMAIN: &[u8] = b"rta-event-v1";
const SOFTWARE_CHAIN_DOMAIN: &[u8] = b"rta-software-chain-v1";
const POLICY_DOMAIN: &[u8] = b"rta-policy-v1";
const SYNTHETIC_RECORD_DOMAIN: &[u8] = b"rta-synthetic-record-v1";
const CLASSIFIED_TPM_EVENT_DOMAIN: &[u8] = b"rta-classified-event-v1";
const FINAL_SUMMARY_DOMAIN: &[u8] = b"rta-final-summary-v1";
const SESSION_START_DOMAIN: &[u8] = b"rta-session-start-v1";

pub const RUNTIME_SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const ZERO_CHAIN_HEAD: [u8; 32] = [0u8; 32];

fn default_profile_mode() -> String {
    String::from("minimal-behaviour")
}

fn default_attestation_backend() -> String {
    String::from("none")
}

fn default_attestation_mode() -> String {
    String::from("software-chain")
}

fn default_fail_on_denied() -> bool {
    true
}

fn default_fail_on_drops() -> bool {
    true
}

fn default_unknown_workload_index() -> u32 {
    UNKNOWN_WORKLOAD_INDEX
}

fn encode_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn encode_bool(buf: &mut Vec<u8>, value: bool) {
    encode_u8(buf, u8::from(value));
}

fn encode_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn encode_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn encode_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("canonical value too large to encode");
    encode_u32(buf, len);
    buf.extend_from_slice(value);
}

fn encode_str(buf: &mut Vec<u8>, value: &str) {
    encode_bytes(buf, value.as_bytes());
}

fn encode_opt_str(buf: &mut Vec<u8>, value: &Option<String>) {
    match value {
        Some(value) => {
            encode_bool(buf, true);
            encode_str(buf, value);
        }
        None => encode_bool(buf, false),
    }
}

fn encode_str_list(buf: &mut Vec<u8>, values: &[String]) {
    let len = u32::try_from(values.len()).expect("canonical list too large to encode");
    encode_u32(buf, len);
    for value in values {
        encode_str(buf, value);
    }
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted
}

fn is_empty_or_unknown_path(path: &str) -> bool {
    let trimmed = path.trim();
    trimmed.is_empty() || trimmed == "<unknown>"
}

fn bytes_to_lossy_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn bytes_to_lossy_string_len(bytes: &[u8], len: u32) -> String {
    let max = usize::min(len as usize, bytes.len());
    bytes_to_lossy_string(&bytes[..max])
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEventType {
    Fork,
    Exec,
    Unknown(u32),
}

impl RuntimeEventType {
    pub fn from_raw(raw: u32) -> Self {
        if raw == EventType::Fork as u32 {
            Self::Fork
        } else if raw == EventType::Exec as u32 {
            Self::Exec
        } else {
            Self::Unknown(raw)
        }
    }

    pub fn is_exec(self) -> bool {
        matches!(self, Self::Exec)
    }

    pub fn policy_name(self) -> String {
        match self {
            Self::Fork => String::from("fork"),
            Self::Exec => String::from("exec"),
            Self::Unknown(raw) => format!("unknown-{raw}"),
        }
    }

    fn canonical_encode(self, buf: &mut Vec<u8>) {
        match self {
            Self::Fork => encode_u8(buf, 1),
            Self::Exec => encode_u8(buf, 2),
            Self::Unknown(raw) => {
                encode_u8(buf, 255);
                encode_u32(buf, raw);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EventClassification {
    Acceptable,
    Suspicious,
    Denied,
}

impl EventClassification {
    fn canonical_encode(self, buf: &mut Vec<u8>) {
        let value = match self {
            Self::Acceptable => 1,
            Self::Suspicious => 2,
            Self::Denied => 3,
        };
        encode_u8(buf, value);
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SyntheticRecordType {
    MonitorStart,
    PolicyLoaded,
    WorkloadTargetBound,
    MonitorStop,
}

impl SyntheticRecordType {
    fn canonical_encode(self, buf: &mut Vec<u8>) {
        let value = match self {
            Self::MonitorStart => 1,
            Self::PolicyLoaded => 2,
            Self::WorkloadTargetBound => 3,
            Self::MonitorStop => 4,
        };
        encode_u8(buf, value);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassificationResult {
    pub classification: EventClassification,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    #[serde(default = "default_unknown_workload_index")]
    pub workload_index: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,

    pub event_type: RuntimeEventType,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub cpu: u32,
    pub comm: String,
    pub exe_path: String,
}

impl RuntimeEvent {
    pub fn from_raw_event(raw: &Event, workload_id: Option<String>) -> Self {
        Self {
            workload_index: raw.workload_index,
            workload_id,
            event_type: RuntimeEventType::from_raw(raw.event_type),
            timestamp_ns: raw.ts_ns,
            cgroup_id: raw.cgroup_id,
            pid: raw.pid,
            tgid: raw.tgid,
            ppid: raw.ppid,
            cpu: raw.cpu,
            comm: bytes_to_lossy_string(&raw.comm),
            exe_path: bytes_to_lossy_string_len(&raw.filename, raw.filename_len),
        }
    }

    fn canonical_bytes(&self, session_id: &[u8; 32], seq_no: u64) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(EVENT_DOMAIN);
        buf.extend_from_slice(session_id);
        encode_u64(&mut buf, seq_no);

        self.event_type.canonical_encode(&mut buf);
        encode_u64(&mut buf, self.timestamp_ns);
        encode_u64(&mut buf, self.cgroup_id);
        encode_u32(&mut buf, self.pid);
        encode_u32(&mut buf, self.tgid);
        encode_u32(&mut buf, self.ppid);
        encode_u32(&mut buf, self.cpu);
        encode_u32(&mut buf, self.workload_index);
        encode_opt_str(&mut buf, &self.workload_id);
        encode_str(&mut buf, &self.comm);
        encode_str(&mut buf, &self.exe_path);

        buf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AcceptablePolicy {
    #[serde(default)]
    pub exec_paths: Vec<String>,

    #[serde(default)]
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SuspiciousPolicy {
    /// Historical name kept for policy compatibility.
    ///
    /// In this design, `unknown_exec_path = true` means that an exec event is
    /// suspicious unless its executable path is explicitly present in
    /// `acceptable.exec_paths`. This covers both empty/unknown paths and known
    /// but unapproved paths such as `/tmp/evil`.
    #[serde(default)]
    pub unknown_exec_path: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DeniedPolicy {
    #[serde(default)]
    pub exec_paths: Vec<String>,

    #[serde(default)]
    pub comm_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationPolicy {
    #[serde(default = "default_attestation_backend")]
    pub backend: String,

    #[serde(default = "default_attestation_mode")]
    pub mode: String,

    #[serde(default)]
    pub fail_on_suspicious: bool,

    #[serde(default = "default_fail_on_denied")]
    pub fail_on_denied: bool,

    #[serde(default = "default_fail_on_drops")]
    pub fail_on_drops: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_pcr: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_bank: Option<String>,

    #[serde(default)]
    pub extend_on: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_tpm_error: Option<bool>,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            backend: default_attestation_backend(),
            mode: default_attestation_mode(),
            fail_on_suspicious: false,
            fail_on_denied: true,
            fail_on_drops: true,
            runtime_pcr: None,
            hash_bank: None,
            extend_on: Vec::new(),
            fail_on_tpm_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    #[serde(default)]
    pub workload_id: String,

    #[serde(default = "default_profile_mode")]
    pub profile_mode: String,

    #[serde(default)]
    pub acceptable: AcceptablePolicy,

    #[serde(default)]
    pub suspicious: SuspiciousPolicy,

    #[serde(default)]
    pub denied: DeniedPolicy,

    #[serde(default)]
    pub attestation: AttestationPolicy,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            workload_id: String::new(),
            profile_mode: default_profile_mode(),
            acceptable: AcceptablePolicy::default(),
            suspicious: SuspiciousPolicy::default(),
            denied: DeniedPolicy::default(),
            attestation: AttestationPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEvent {
    pub session_id: String,
    pub seq_no: u64,
    pub event: RuntimeEvent,
    pub classification: EventClassification,
    pub rule_id: String,
    pub reason: String,
    pub event_hash: String,
    pub software_chain_head: String,
    pub tpm_extended: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_extend_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSyntheticRecord {
    pub session_id: String,
    pub seq_no: u64,
    pub record_type: SyntheticRecordType,
    pub reason: String,
    pub record_hash: String,
    pub software_chain_head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "record_kind", content = "record", rename_all = "kebab-case")]
pub enum EvidenceRecord {
    RuntimeEvent(EvidenceEvent),
    Synthetic(EvidenceSyntheticRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TpmSummary {
    pub enabled: bool,
    pub hash_bank: String,
    pub runtime_pcr: u32,

    #[serde(default)]
    pub reset_pcr: bool,

    #[serde(default)]
    pub event_extend_count: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_pcr: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_session_start_pcr: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_pcr: Option<String>,

    pub session_start_digest: String,
    pub final_summary_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSummary {
    pub schema_version: u32,
    pub session_id: String,
    pub workload_id: String,
    pub collection_mode: String,
    pub policy_hash: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_config_hash: Option<String>,

    pub attestation_status: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,

    pub event_count: u64,
    #[serde(default)]
    pub synthetic_record_count: u64,
    pub acceptable_count: u64,
    pub suspicious_count: u64,
    pub denied_count: u64,
    pub dropped_events: u64,
    pub software_chain_head: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_summary_digest: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm: Option<TpmSummary>,
}

/// Shared sequence, count, and software-chain state for evidence replay.
///
/// Runtime and synthetic evidence records use one contiguous sequence stream
/// and update the same software hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceState {
    pub session_id: [u8; 32],
    pub next_seq_no: u64,
    pub event_count: u64,
    pub synthetic_record_count: u64,
    pub acceptable_count: u64,
    pub suspicious_count: u64,
    pub denied_count: u64,
    pub software_chain_head: [u8; 32],
}

impl RuntimeEvidenceState {
    pub fn new(session_id: [u8; 32]) -> Self {
        Self {
            session_id,
            next_seq_no: 1,
            event_count: 0,
            synthetic_record_count: 0,
            acceptable_count: 0,
            suspicious_count: 0,
            denied_count: 0,
            software_chain_head: ZERO_CHAIN_HEAD,
        }
    }

    pub fn observe_classification(&mut self, classification: EventClassification) {
        self.event_count += 1;

        match classification {
            EventClassification::Acceptable => self.acceptable_count += 1,
            EventClassification::Suspicious => self.suspicious_count += 1,
            EventClassification::Denied => self.denied_count += 1,
        }
    }

    pub fn observe_synthetic_record(&mut self) {
        self.synthetic_record_count += 1;
    }

    pub fn advance_sequence(&mut self) -> u64 {
        let seq_no = self.next_seq_no;
        self.next_seq_no += 1;
        seq_no
    }

    pub fn update_chain(&mut self, record_hash: [u8; 32]) -> [u8; 32] {
        self.software_chain_head = update_software_chain(self.software_chain_head, record_hash);
        self.software_chain_head
    }
}

/// Generate a cryptographically random session ID.
///
/// This intentionally fails closed if the OS random source is unavailable.
/// The convenience `generate_session_id` wrapper panics on failure, while
/// `try_generate_session_id` allows callers to handle errors explicitly.
pub fn try_generate_session_id() -> Result<[u8; 32]> {
    let mut session_id = [0u8; 32];
    let mut file = File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    file.read_exact(&mut session_id)
        .context("failed to read 32 bytes from /dev/urandom")?;
    Ok(session_id)
}

pub fn generate_session_id() -> [u8; 32] {
    try_generate_session_id().expect("failed to generate runtime attestation session ID")
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(anyhow!("expected 64 hex chars, got {}", value.len()));
    }

    let mut out = [0u8; 32];
    let bytes = value.as_bytes();

    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| {
            anyhow!(
                "invalid hex character `{}` at position {}",
                chunk[0] as char,
                idx * 2
            )
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| {
            anyhow!(
                "invalid hex character `{}` at position {}",
                chunk[1] as char,
                idx * 2 + 1
            )
        })?;
        out[idx] = (hi << 4) | lo;
    }

    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn event_hash(session_id: &[u8; 32], seq_no: u64, event: &RuntimeEvent) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(event.canonical_bytes(session_id, seq_no));
    finalize_sha256(hasher)
}

pub fn synthetic_record_hash(
    session_id: &[u8; 32],
    seq_no: u64,
    record_type: SyntheticRecordType,
    reason: &str,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(SYNTHETIC_RECORD_DOMAIN);
    buf.extend_from_slice(session_id);
    encode_u64(&mut buf, seq_no);
    record_type.canonical_encode(&mut buf);
    encode_str(&mut buf, reason);

    let mut hasher = Sha256::new();
    hasher.update(buf);
    finalize_sha256(hasher)
}

pub fn update_software_chain(old_head: [u8; 32], record_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOFTWARE_CHAIN_DOMAIN);
    hasher.update(old_head);
    hasher.update(record_hash);
    finalize_sha256(hasher)
}

pub fn classified_tpm_digest(
    session_id: &[u8; 32],
    seq_no: u64,
    event_hash: [u8; 32],
    classification: EventClassification,
    rule_id: &str,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(CLASSIFIED_TPM_EVENT_DOMAIN);
    buf.extend_from_slice(session_id);
    encode_u64(&mut buf, seq_no);
    classification.canonical_encode(&mut buf);
    encode_str(&mut buf, rule_id);
    buf.extend_from_slice(&event_hash);

    let mut hasher = Sha256::new();
    hasher.update(buf);
    finalize_sha256(hasher)
}

pub fn session_start_digest(
    session_id: &[u8; 32],
    policy_hash: [u8; 32],
    workload_id: &str,
    collection_mode: &str,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(SESSION_START_DOMAIN);
    buf.extend_from_slice(session_id);
    buf.extend_from_slice(&policy_hash);
    encode_str(&mut buf, workload_id);
    encode_str(&mut buf, collection_mode);

    let mut hasher = Sha256::new();
    hasher.update(buf);
    finalize_sha256(hasher)
}

pub fn replay_pcr_extend(old_pcr: [u8; 32], digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(old_pcr);
    hasher.update(digest);
    finalize_sha256(hasher)
}

#[allow(clippy::too_many_arguments)]
pub fn final_summary_digest(
    session_id: &[u8; 32],
    software_chain_head: [u8; 32],
    event_count: u64,
    synthetic_record_count: u64,
    acceptable_count: u64,
    suspicious_count: u64,
    denied_count: u64,
    dropped_events: u64,
    policy_hash: [u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(FINAL_SUMMARY_DOMAIN);
    buf.extend_from_slice(session_id);
    buf.extend_from_slice(&software_chain_head);
    encode_u64(&mut buf, event_count);
    encode_u64(&mut buf, synthetic_record_count);
    encode_u64(&mut buf, acceptable_count);
    encode_u64(&mut buf, suspicious_count);
    encode_u64(&mut buf, denied_count);
    encode_u64(&mut buf, dropped_events);
    buf.extend_from_slice(&policy_hash);

    let mut hasher = Sha256::new();
    hasher.update(buf);
    finalize_sha256(hasher)
}

pub fn policy_hash(policy: &RuntimePolicy) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DOMAIN);
    hasher.update(policy_canonical_bytes(policy));
    finalize_sha256(hasher)
}

pub fn classify_event(event: &RuntimeEvent, policy: &RuntimePolicy) -> ClassificationResult {
    // Denied rules always win.
    if let Some(reason) = deny_by_exec_path(event, policy) {
        return ClassificationResult {
            classification: EventClassification::Denied,
            rule_id: String::from("deny-exec-path"),
            reason,
        };
    }

    if let Some(reason) = deny_by_comm(event, policy) {
        return ClassificationResult {
            classification: EventClassification::Denied,
            rule_id: String::from("deny-comm"),
            reason,
        };
    }

    // For exec events, an executable path must be explicitly acceptable when
    // `unknown_exec_path` is enabled. Listing "exec" in acceptable.event_types
    // must not accidentally approve all executable paths.
    if event.event_type.is_exec() {
        if let Some(reason) = acceptable_by_exec_path(event, policy) {
            return ClassificationResult {
                classification: EventClassification::Acceptable,
                rule_id: String::from("acceptable-exec-path"),
                reason,
            };
        }

        if policy.suspicious.unknown_exec_path {
            return ClassificationResult {
                classification: EventClassification::Suspicious,
                rule_id: String::from("unknown-exec-path"),
                reason: unapproved_exec_reason(&event.exe_path),
            };
        }

        if let Some(reason) = acceptable_by_event_type(event, policy) {
            return ClassificationResult {
                classification: EventClassification::Acceptable,
                rule_id: String::from("acceptable-event-type"),
                reason,
            };
        }

        return ClassificationResult {
            classification: EventClassification::Suspicious,
            rule_id: String::from("default-suspicious"),
            reason: String::from("exec event did not match acceptable policy rules"),
        };
    }

    if let Some(reason) = acceptable_by_event_type(event, policy) {
        return ClassificationResult {
            classification: EventClassification::Acceptable,
            rule_id: String::from("acceptable-event-type"),
            reason,
        };
    }

    if let Some(reason) = acceptable_by_exec_path(event, policy) {
        return ClassificationResult {
            classification: EventClassification::Acceptable,
            rule_id: String::from("acceptable-exec-path"),
            reason,
        };
    }

    ClassificationResult {
        classification: EventClassification::Suspicious,
        rule_id: String::from("default-suspicious"),
        reason: String::from("event did not match acceptable or denied policy rules"),
    }
}

fn unapproved_exec_reason(exe_path: &str) -> String {
    if is_empty_or_unknown_path(exe_path) {
        String::from("exec path is empty or unknown")
    } else {
        format!("exec path {exe_path} is not in acceptable exec-path policy")
    }
}

fn deny_by_exec_path(event: &RuntimeEvent, policy: &RuntimePolicy) -> Option<String> {
    policy
        .denied
        .exec_paths
        .iter()
        .any(|path| path == &event.exe_path)
        .then(|| format!("exec path {} is denied", event.exe_path))
}

fn deny_by_comm(event: &RuntimeEvent, policy: &RuntimePolicy) -> Option<String> {
    policy
        .denied
        .comm_names
        .iter()
        .any(|name| name == &event.comm)
        .then(|| format!("comm {} is denied", event.comm))
}

fn acceptable_by_exec_path(event: &RuntimeEvent, policy: &RuntimePolicy) -> Option<String> {
    policy
        .acceptable
        .exec_paths
        .iter()
        .any(|path| path == &event.exe_path)
        .then(|| format!("exec path {} is acceptable", event.exe_path))
}

fn acceptable_by_event_type(event: &RuntimeEvent, policy: &RuntimePolicy) -> Option<String> {
    let event_type = event.event_type.policy_name();

    policy
        .acceptable
        .event_types
        .iter()
        .any(|candidate| candidate == &event_type)
        .then(|| format!("event type {event_type} is acceptable"))
}

fn policy_canonical_bytes(policy: &RuntimePolicy) -> Vec<u8> {
    let mut buf = Vec::new();

    encode_str(&mut buf, &policy.workload_id);
    encode_str(&mut buf, &policy.profile_mode);

    let acceptable_exec_paths = sorted_strings(&policy.acceptable.exec_paths);
    encode_str_list(&mut buf, &acceptable_exec_paths);

    let acceptable_event_types = sorted_strings(&policy.acceptable.event_types);
    encode_str_list(&mut buf, &acceptable_event_types);

    encode_bool(&mut buf, policy.suspicious.unknown_exec_path);

    let denied_exec_paths = sorted_strings(&policy.denied.exec_paths);
    encode_str_list(&mut buf, &denied_exec_paths);

    let denied_comm_names = sorted_strings(&policy.denied.comm_names);
    encode_str_list(&mut buf, &denied_comm_names);

    encode_str(&mut buf, &policy.attestation.backend);
    encode_str(&mut buf, &policy.attestation.mode);
    encode_bool(&mut buf, policy.attestation.fail_on_suspicious);
    encode_bool(&mut buf, policy.attestation.fail_on_denied);
    encode_bool(&mut buf, policy.attestation.fail_on_drops);

    match policy.attestation.runtime_pcr {
        Some(value) => {
            encode_bool(&mut buf, true);
            encode_u32(&mut buf, value);
        }
        None => encode_bool(&mut buf, false),
    }

    encode_opt_str(&mut buf, &policy.attestation.hash_bank);

    let extend_on = sorted_strings(&policy.attestation.extend_on);
    encode_str_list(&mut buf, &extend_on);

    match policy.attestation.fail_on_tpm_error {
        Some(value) => {
            encode_bool(&mut buf, true);
            encode_bool(&mut buf, value);
        }
        None => encode_bool(&mut buf, false),
    }

    buf
}

#[cfg(all(test, feature = "user"))]
mod tests {
    use super::*;

    fn sample_event() -> RuntimeEvent {
        RuntimeEvent {
            workload_index: 3,
            workload_id: Some(String::from("fastapi")),
            event_type: RuntimeEventType::Exec,
            timestamp_ns: 42,
            cgroup_id: 99,
            pid: 123,
            tgid: 456,
            ppid: 789,
            cpu: 2,
            comm: String::from("python"),
            exe_path: String::from("/usr/local/bin/python"),
        }
    }

    fn sample_policy() -> RuntimePolicy {
        RuntimePolicy {
            workload_id: String::from("fastapi"),
            profile_mode: String::from("minimal-behaviour"),
            acceptable: AcceptablePolicy {
                exec_paths: Vec::from([
                    String::from("/usr/local/bin/python"),
                    String::from("/usr/local/bin/uvicorn"),
                ]),
                event_types: Vec::from([String::from("exec"), String::from("fork")]),
            },
            suspicious: SuspiciousPolicy {
                unknown_exec_path: true,
            },
            denied: DeniedPolicy {
                exec_paths: Vec::from([String::from("/bin/sh")]),
                comm_names: Vec::from([String::from("sh")]),
            },
            attestation: AttestationPolicy::default(),
        }
    }

    #[test]
    fn event_hash_is_deterministic() {
        let event = sample_event();
        let session = [7u8; 32];

        let left = event_hash(&session, 9, &event);
        let right = event_hash(&session, 9, &event);

        assert_eq!(left, right);
    }

    #[test]
    fn event_hash_depends_on_session() {
        let event = sample_event();

        let left = event_hash(&[1u8; 32], 9, &event);
        let right = event_hash(&[2u8; 32], 9, &event);

        assert_ne!(left, right);
    }

    #[test]
    fn event_hash_depends_on_sequence_number() {
        let event = sample_event();
        let session = [7u8; 32];

        let left = event_hash(&session, 1, &event);
        let right = event_hash(&session, 2, &event);

        assert_ne!(left, right);
    }

    #[test]
    fn software_chain_changes_with_record_hash() {
        let left = update_software_chain([1u8; 32], [2u8; 32]);
        let right = update_software_chain([1u8; 32], [3u8; 32]);

        assert_ne!(left, right);
    }

    #[test]
    fn synthetic_record_hash_is_deterministic() {
        let session = [7u8; 32];

        let left = synthetic_record_hash(
            &session,
            1,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );
        let right = synthetic_record_hash(
            &session,
            1,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );

        assert_eq!(left, right);
    }

    #[test]
    fn synthetic_record_hash_depends_on_all_inputs() {
        let session = [7u8; 32];
        let baseline = synthetic_record_hash(
            &session,
            1,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );

        assert_ne!(
            baseline,
            synthetic_record_hash(
                &[8u8; 32],
                1,
                SyntheticRecordType::MonitorStart,
                "monitor session started"
            )
        );
        assert_ne!(
            baseline,
            synthetic_record_hash(
                &session,
                2,
                SyntheticRecordType::MonitorStart,
                "monitor session started"
            )
        );
        assert_ne!(
            baseline,
            synthetic_record_hash(
                &session,
                1,
                SyntheticRecordType::MonitorStop,
                "monitor session started"
            )
        );
        assert_ne!(
            baseline,
            synthetic_record_hash(
                &session,
                1,
                SyntheticRecordType::MonitorStart,
                "different reason"
            )
        );
    }

    #[test]
    fn hex_round_trip_32_bytes() {
        let input = [0xabu8; 32];
        let encoded = hex_encode(&input);
        let decoded = hex_decode_32(&encoded).expect("decode");

        assert_eq!(input, decoded);
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode_32("abcd").is_err());
    }

    #[test]
    fn evidence_record_runtime_event_ser_de_round_trip() {
        let runtime_event = sample_event();
        let session_id = hex_encode(&[7u8; 32]);
        let event_hash_bytes = event_hash(&[7u8; 32], 1, &runtime_event);
        let chain_head = update_software_chain(ZERO_CHAIN_HEAD, event_hash_bytes);
        let record = EvidenceRecord::RuntimeEvent(EvidenceEvent {
            session_id,
            seq_no: 1,
            event: runtime_event,
            classification: EventClassification::Acceptable,
            rule_id: String::from("acceptable-exec-path"),
            reason: String::from("test"),
            event_hash: hex_encode(&event_hash_bytes),
            software_chain_head: hex_encode(&chain_head),
            tpm_extended: false,
            tpm_extend_index: None,
        });

        let encoded = serde_json::to_string(&record).expect("serialize");
        assert!(encoded.contains("\"record_kind\":\"runtime-event\""));
        let decoded = serde_json::from_str::<EvidenceRecord>(&encoded).expect("deserialize");

        assert_eq!(decoded, record);
    }

    #[test]
    fn evidence_record_synthetic_ser_de_round_trip() {
        let session = [7u8; 32];
        let record_hash = synthetic_record_hash(
            &session,
            1,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );
        let chain_head = update_software_chain(ZERO_CHAIN_HEAD, record_hash);
        let record = EvidenceRecord::Synthetic(EvidenceSyntheticRecord {
            session_id: hex_encode(&session),
            seq_no: 1,
            record_type: SyntheticRecordType::MonitorStart,
            reason: String::from("monitor session started"),
            record_hash: hex_encode(&record_hash),
            software_chain_head: hex_encode(&chain_head),
        });

        let encoded = serde_json::to_string(&record).expect("serialize");
        assert!(encoded.contains("\"record_kind\":\"synthetic\""));
        let decoded = serde_json::from_str::<EvidenceRecord>(&encoded).expect("deserialize");

        assert_eq!(decoded, record);
    }

    #[test]
    fn runtime_summary_parses_without_synthetic_record_count() {
        let json = r#"{
            "schema_version": 1,
            "session_id": "0707070707070707070707070707070707070707070707070707070707070707",
            "workload_id": "workload-a",
            "collection_mode": "scoped",
            "policy_hash": "0808080808080808080808080808080808080808080808080808080808080808",
            "attestation_status": "passed",
            "event_count": 0,
            "acceptable_count": 0,
            "suspicious_count": 0,
            "denied_count": 0,
            "dropped_events": 0,
            "software_chain_head": "0000000000000000000000000000000000000000000000000000000000000000"
        }"#;

        let summary = serde_json::from_str::<RuntimeSummary>(json).expect("summary");

        assert_eq!(summary.synthetic_record_count, 0);
        assert!(summary.tpm.is_none());
    }

    #[test]
    fn tpm_summary_parses_without_event_extend_count() {
        let json = r#"{
            "enabled": true,
            "hash_bank": "sha256",
            "runtime_pcr": 23,
            "reset_pcr": true,
            "initial_pcr": "0000000000000000000000000000000000000000000000000000000000000000",
            "after_session_start_pcr": "1111111111111111111111111111111111111111111111111111111111111111",
            "final_pcr": "2222222222222222222222222222222222222222222222222222222222222222",
            "session_start_digest": "3333333333333333333333333333333333333333333333333333333333333333",
            "final_summary_digest": "4444444444444444444444444444444444444444444444444444444444444444"
        }"#;

        let summary = serde_json::from_str::<TpmSummary>(json).expect("tpm summary");

        assert_eq!(summary.event_extend_count, 0);
    }

    #[test]
    fn denied_exec_path_overrides_acceptable_exec_path() {
        let mut policy = sample_policy();
        policy
            .denied
            .exec_paths
            .push(String::from("/usr/local/bin/python"));

        let result = classify_event(&sample_event(), &policy);

        assert_eq!(result.classification, EventClassification::Denied);
        assert_eq!(result.rule_id, "deny-exec-path");
    }

    #[test]
    fn denied_comm_is_classified_as_denied() {
        let mut policy = sample_policy();
        policy.denied.exec_paths.clear();
        policy.denied.comm_names.push(String::from("python"));

        let result = classify_event(&sample_event(), &policy);

        assert_eq!(result.classification, EventClassification::Denied);
        assert_eq!(result.rule_id, "deny-comm");
    }

    #[test]
    fn acceptable_exec_path_is_classified_as_acceptable() {
        let policy = sample_policy();

        let result = classify_event(&sample_event(), &policy);

        assert_eq!(result.classification, EventClassification::Acceptable);
        assert_eq!(result.rule_id, "acceptable-exec-path");
    }

    #[test]
    fn acceptable_event_type_is_classified_as_acceptable_for_fork() {
        let mut policy = sample_policy();
        policy.acceptable.exec_paths.clear();

        let mut event = sample_event();
        event.event_type = RuntimeEventType::Fork;
        event.exe_path = String::new();

        let result = classify_event(&event, &policy);

        assert_eq!(result.classification, EventClassification::Acceptable);
        assert_eq!(result.rule_id, "acceptable-event-type");
    }

    #[test]
    fn empty_exec_path_becomes_suspicious_when_enabled() {
        let mut policy = sample_policy();
        policy.acceptable.exec_paths.clear();
        policy.acceptable.event_types.clear();

        let mut event = sample_event();
        event.exe_path = String::new();

        let result = classify_event(&event, &policy);

        assert_eq!(result.classification, EventClassification::Suspicious);
        assert_eq!(result.rule_id, "unknown-exec-path");
        assert!(result.reason.contains("empty or unknown"));
    }

    #[test]
    fn unapproved_exec_path_becomes_suspicious_when_enabled() {
        let mut policy = sample_policy();
        policy.acceptable.exec_paths = Vec::from([String::from("/usr/local/bin/python")]);
        policy.acceptable.event_types = Vec::from([String::from("exec")]);
        policy.suspicious.unknown_exec_path = true;

        let mut event = sample_event();
        event.exe_path = String::from("/tmp/evil");

        let result = classify_event(&event, &policy);

        assert_eq!(result.classification, EventClassification::Suspicious);
        assert_eq!(result.rule_id, "unknown-exec-path");
        assert!(result.reason.contains("not in acceptable exec-path policy"));
    }

    #[test]
    fn exec_event_type_can_be_acceptable_when_unknown_exec_path_check_disabled() {
        let mut policy = sample_policy();
        policy.acceptable.exec_paths.clear();
        policy.acceptable.event_types = Vec::from([String::from("exec")]);
        policy.suspicious.unknown_exec_path = false;

        let mut event = sample_event();
        event.exe_path = String::from("/tmp/not-profiled");

        let result = classify_event(&event, &policy);

        assert_eq!(result.classification, EventClassification::Acceptable);
        assert_eq!(result.rule_id, "acceptable-event-type");
    }

    #[test]
    fn policy_hash_is_deterministic() {
        let policy = sample_policy();

        let left = policy_hash(&policy);
        let right = policy_hash(&policy);

        assert_eq!(left, right);
    }

    #[test]
    fn policy_hash_sorts_list_fields() {
        let mut left = sample_policy();
        let mut right = sample_policy();

        left.acceptable.exec_paths = Vec::from([
            String::from("/usr/local/bin/python"),
            String::from("/usr/local/bin/uvicorn"),
        ]);
        right.acceptable.exec_paths = Vec::from([
            String::from("/usr/local/bin/uvicorn"),
            String::from("/usr/local/bin/python"),
        ]);

        assert_eq!(policy_hash(&left), policy_hash(&right));
    }

    #[test]
    fn classified_tpm_digest_depends_on_classification() {
        let session = [1u8; 32];
        let event_digest = [2u8; 32];

        let suspicious = classified_tpm_digest(
            &session,
            1,
            event_digest,
            EventClassification::Suspicious,
            "unknown-exec-path",
        );
        let denied = classified_tpm_digest(
            &session,
            1,
            event_digest,
            EventClassification::Denied,
            "unknown-exec-path",
        );

        assert_ne!(suspicious, denied);
    }

    #[test]
    fn session_start_digest_is_deterministic() {
        let session = [1u8; 32];
        let policy = [2u8; 32];

        let left = session_start_digest(&session, policy, "workload-a", "scoped");
        let right = session_start_digest(&session, policy, "workload-a", "scoped");

        assert_eq!(left, right);
    }

    #[test]
    fn session_start_digest_depends_on_all_inputs() {
        let session = [1u8; 32];
        let policy = [2u8; 32];
        let baseline = session_start_digest(&session, policy, "workload-a", "scoped");

        assert_ne!(
            baseline,
            session_start_digest(&[3u8; 32], policy, "workload-a", "scoped")
        );
        assert_ne!(
            baseline,
            session_start_digest(&session, [4u8; 32], "workload-a", "scoped")
        );
        assert_ne!(
            baseline,
            session_start_digest(&session, policy, "workload-b", "scoped")
        );
        assert_ne!(
            baseline,
            session_start_digest(&session, policy, "workload-a", "host-wide")
        );
    }

    #[test]
    fn replay_pcr_extend_matches_sha256_concatenation() {
        let old_pcr = [1u8; 32];
        let digest = [2u8; 32];

        let mut hasher = Sha256::new();
        hasher.update(old_pcr);
        hasher.update(digest);
        let expected = finalize_sha256(hasher);

        assert_eq!(replay_pcr_extend(old_pcr, digest), expected);
    }

    #[test]
    fn final_summary_digest_depends_on_counts() {
        let session = [1u8; 32];
        let chain_head = [2u8; 32];
        let policy = [3u8; 32];

        let left = final_summary_digest(&session, chain_head, 10, 4, 9, 1, 0, 0, policy);
        let runtime_count_changed =
            final_summary_digest(&session, chain_head, 11, 4, 9, 1, 0, 0, policy);
        let synthetic_count_changed =
            final_summary_digest(&session, chain_head, 10, 5, 9, 1, 0, 0, policy);
        let classification_counts_changed =
            final_summary_digest(&session, chain_head, 10, 4, 8, 2, 0, 0, policy);

        assert_ne!(left, runtime_count_changed);
        assert_ne!(left, synthetic_count_changed);
        assert_ne!(left, classification_counts_changed);
    }

    #[test]
    fn evidence_state_tracks_counts_and_chain() {
        let mut state = RuntimeEvidenceState::new([4u8; 32]);

        let seq_no = state.advance_sequence();
        assert_eq!(seq_no, 1);
        assert_eq!(state.next_seq_no, 2);

        state.observe_classification(EventClassification::Acceptable);
        state.observe_classification(EventClassification::Suspicious);
        state.observe_classification(EventClassification::Denied);

        assert_eq!(state.event_count, 3);
        assert_eq!(state.synthetic_record_count, 0);
        assert_eq!(state.acceptable_count, 1);
        assert_eq!(state.suspicious_count, 1);
        assert_eq!(state.denied_count, 1);

        state.observe_synthetic_record();
        assert_eq!(state.synthetic_record_count, 1);

        let old_head = state.software_chain_head;
        let new_head = state.update_chain([9u8; 32]);
        assert_ne!(old_head, new_head);
        assert_eq!(state.software_chain_head, new_head);
    }
}
