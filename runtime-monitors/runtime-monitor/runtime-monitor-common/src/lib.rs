#![no_std]

use bytemuck::{Pod, Zeroable};

pub const TASK_COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const FILENAME_TRUNCATED: u32 = 1;

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
pub struct Event {
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
