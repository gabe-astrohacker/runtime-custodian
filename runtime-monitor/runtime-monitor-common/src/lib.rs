#![no_std]

#[cfg(feature = "user")]
extern crate std;

use bytemuck::{Pod, Zeroable};

pub const TASK_COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 512;
pub const FILENAME_TRUNCATED: u32 = 1;
pub const COLLECTION_MODE_SCOPED: u32 = 0;
pub const COLLECTION_MODE_HOST_WIDE: u32 = 1;
pub const UNKNOWN_WORKLOAD_INDEX: u32 = u32::MAX;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventType {
    Fork = 1,
    Exec = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TargetWorkload {
    pub workload_index: u32,
    pub flags: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TargetWorkload {}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MonitorState {
    pub seq: u64,
    pub lost: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MonitorState {}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Event {
    pub seq: u64,
    pub lost: u64,
    pub ts_ns: u64,
    pub cgroup_id: u64,

    pub event_type: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub cpu: u32,
    pub workload_index: u32,
    pub workload_flags: u32,

    pub filename_len: u32,
    pub filename_flags: u32,
    pub filename_read_error: i32,
    pub reserved: u32,
    pub reserved2: u32,

    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; PATH_LEN],
}
// Optional: userspace-only convenience impls can live behind cfg(feature = "user")

#[cfg(feature = "user")]
pub mod evidence;

#[cfg(feature = "user")]
pub use evidence::{
    AcceptablePolicy, AttestationPolicy, ClassificationResult, DeniedPolicy, EventClassification,
    EvidenceEvent, EvidenceRecord, EvidenceSyntheticRecord, RuntimeEvent, RuntimePolicy,
    RuntimeSummary, SuspiciousPolicy, SyntheticRecordType, TpmQuoteSummary, TpmSummary,
    classified_tpm_digest, classify_event, event_hash, final_summary_digest, generate_session_id,
    hex_decode_32, hex_encode, policy_hash, replay_pcr_extend, session_start_digest,
    synthetic_record_hash, update_software_chain,
};
