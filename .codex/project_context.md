# Codex Project Context

## Project

This repo is for an MEng FYP prototype: Keylime-compatible workload-scoped runtime attestation using eBPF.

Goal: collect runtime evidence for selected container workloads, then verify that evidence against a policy. This is not a prevention system.

## Architecture

Three separate roles:

1. eBPF monitor
   - Runs on the attested node.
   - Currently monitors `sched_process_exec`.
   - May filter by measurement scope, e.g. target cgroup/workload.
   - Must not apply allow/deny policy.

2. Runtime reporter
   - Runs on the attested node.
   - Receives eBPF events.
   - Writes canonical JSONL evidence and summaries/digests.
   - Must not decide whether an event is allowed or forbidden.

3. Runtime verifier
   - Conceptually external to the attested node.
   - Reads evidence and verifier policy.
   - Applies allow/deny policy.
   - Outputs ACCEPT or REJECT.

Final intended composition:

    ACCEPT = Keylime attestation passes AND runtime verification passes

For now, Keylime integration is shallow wrapper composition, not deep Keylime modification.

## Critical rules

- Do not put allow/deny policy in eBPF.
- Do not put allow/deny policy in the reporter.
- Reporter records evidence only.
- Verifier makes the security decision.
- Keep diffs small.
- Avoid broad refactors unless explicitly asked.
- Do not use `sudo cargo run`; build normally, then run the built binary with sudo.
- Preserve current behaviour:
  - `/echo` -> `/usr/bin/echo` evidence -> verifier ACCEPT
  - `/bad` -> `/usr/bin/id` evidence -> verifier REJECT

## Workload

V1 workload: Dockerised FastAPI backend.

Endpoints:
- `/ping`: benign
- `/echo`: expected subprocess, executes `/usr/bin/echo`
- `/bad`: deliberate deviation, executes `/usr/bin/id`

## Config split

Collector config is for measurement scope only.

Example concepts:
- `collection_mode`
- `workloads`
- `workload_id`
- `container_name`
- `evidence_out`

Verifier policy is for security decisions only.

Example concepts:
- `workload_id`
- `allowed_exec_paths`
- `forbidden_exec_paths`
- `default_action`

## Collection modes

- `scoped`: emit only configured workload/container cgroups.
- `host-wide`: emit all exec events for evaluation only.

Host-wide evidence must not be treated as workload-scoped attestation evidence unless explicitly overridden.

## Evidence

Reporter JSONL evidence should include relevant fields such as:

- `seq`
- `lost`
- `workload_id`
- `event_type`
- `ts_ns`
- `pid`
- `tgid`
- `cgroup_id`
- `comm`
- `exe_path`
- `filename_read_ok`
- `filename_truncated`
- `filename_read_error`

Reporter output should not include `decision`.

## Verifier should reject if

- workload_id mismatch
- forbidden executable observed
- unknown executable observed when default_action is deny
- sequence gap
- lost > 0
- filename_read_ok is false
- filename_truncated is true
- digest mismatch if summary is supplied
- host-wide evidence is used with workload policy without explicit override

## Tests

Fast tests:
- `cargo test`
- no Docker
- no sudo
- no eBPF loading
- test verifier/evidence logic with fixtures

Integration tests:
- use scripts
- may require Docker, sudo, eBPF
- must run built binary, not `sudo cargo run`

## V1 limitations

- Kernel trusted at monitoring start.
- Current focus is exec-level deviations.
- Pure Python `exec()`/`eval()` without subprocess is not detected.
- argv/openat/mmap/TPM PCR anchoring are stretch/future work unless explicitly requested.