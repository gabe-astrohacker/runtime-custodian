seq: u64
ts_ns: u64
event_type: string        # fork | exec | openat | mmap_exec
pid: u32
tgid: u32
ppid: u32
cpu: u32
cgroup_id: u64
comm: string
exe_path: string optional
target_path: string optional
loss_seen: bool