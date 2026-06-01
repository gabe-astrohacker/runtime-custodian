# runtime-custodian

MEng FYP prototype for Keylime-compatible workload-scoped runtime attestation.

## Architecture

- Aya eBPF tracepoint monitor collects `sched_process_exec` evidence. In scoped mode it filters collection by target cgroup/workload IDs; in host-wide mode it emits all exec events.
- The runtime reporter writes canonical JSONL evidence plus a small runtime summary with sequence/loss state and evidence digest.
- The runtime verifier applies allow/deny policy to the evidence and checks continuity, loss, truncation, and digest state.
- Keylime composition is currently a shallow wrapper script that combines an external Keylime pass/fail result with the runtime verifier result. It is not deep Keylime integration.

## Run

Build:

```bash
./scripts/build_all.sh
```

Start the FastAPI workload:

```bash
./scripts/run_workload.sh
```

Run the scoped monitor in a separate terminal:

```bash
./scripts/run_monitor_scoped.sh
```

Exercise benign and deviation paths:

```bash
curl -fsS http://127.0.0.1:8000/echo
curl -fsS http://127.0.0.1:8000/bad
```

Run the verifier:

```bash
./target/debug/runtime-verifier \
  --policy policies/fastapi-verifier-policy.json \
  --evidence logs/runtime_events.jsonl \
  --summary logs/runtime_events.summary.json
```

Expected scoped behaviour:

- `/echo` produces `/usr/bin/echo` evidence and is accepted by policy.
- `/bad` produces `/usr/bin/id` evidence and is rejected by policy.

## Evaluation

Fast unit tests:

```bash
cargo test
```

Docker/sudo/eBPF integration smoke test:

```bash
./scripts/run_v1_integration_tests.sh
```

Benign and deviation checks:

```bash
./scripts/run_echo_experiment.sh
./scripts/run_bad_experiment.sh
```

Latency measurement:

```bash
./scripts/measure_latency.py --url http://127.0.0.1:8000/echo --requests 100 --out logs/latency.json
./scripts/summarise_latency.py --baseline logs/baseline_latency.json --monitored logs/monitored_latency.json
```

Host-wide versus scoped event volume:

```bash
./scripts/measure_event_volume.sh
```

Evidence summarisation:

```bash
./scripts/count_events.py logs/runtime_events.jsonl
```

## Limitations

- Assumes a trusted kernel and monitor at monitor start.
- Detects exec-level deviations only.
- Pure Python `exec`/`eval` behaviour without subprocess creation is not detected.
- `argv`, `openat`, and `mmap` evidence are not yet covered.
- TPM PCR anchoring of runtime evidence is not yet implemented.

## Current Claim

Workload-scoped eBPF exec evidence detects subprocess-style runtime deviations in a containerised FastAPI workload and reduces host-wide event noise.
