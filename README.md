# runtime-custodian

MEng FYP prototype for **Keylime-compatible workload-scoped runtime attestation**.

The prototype explores whether eBPF-based runtime evidence can improve long-running cloud workload attestation by collecting workload-relevant execution events, reducing host-wide event noise, and applying verifier-side runtime policy checks.

## Architecture

* **Aya eBPF tracepoint monitor**

  * Collects `sched_process_exec` runtime evidence.
  * In `scoped` mode, emits only events from configured workload cgroups.
  * In `host-wide` mode, emits all observed exec events and labels events outside the target workload as unknown.
  * Uses a global atomic sequence counter for emitted evidence ordering.

* **Runtime reporter**

  * Consumes eBPF ring-buffer events.
  * Writes canonical JSONL evidence.
  * Writes a runtime summary containing sequence/loss state, malformed sample count, collection mode, workload ID, and an evidence digest.

* **Runtime verifier**

  * Applies allow/deny runtime policy to collected evidence.
  * Checks sequence continuity, loss state, truncation/malformed evidence, and evidence digest consistency.
  * Accepts benign workload behaviour and rejects policy deviations.

* **Keylime composition**

  * Current Keylime support is a shallow composition wrapper that combines an external Keylime pass/fail result with the runtime verifier result.
  * This is not yet deep Keylime verifier/agent integration.

## Repository layout

```text
policies/
  fastapi-monitor-policy.json      # monitor collector config
  fastapi-verifier-policy.json     # runtime verifier policy

runtime-monitor/
  runtime-monitor-ebpf/            # no_std Aya eBPF program
  runtime-monitor/                 # userspace monitor/reporter
  runtime-verifier/                # runtime evidence verifier
  runtime-monitor-common/          # shared event/state structs

scripts/
  build_all.sh                     # builds workspace and embedded eBPF object
  run_workload.sh                  # starts FastAPI Docker workload
  stop_workload.sh                 # stops FastAPI Docker workload
  integration_lib.py               # shared Python test/experiment harness
  run_v1_integration_tests.py      # correctness smoke tests
  run_performance_experiments.py   # latency and event-volume experiments

logs/
  integration/                     # correctness-test logs/evidence/configs
  experiments/                     # benchmark/experiment JSON, CSV, evidence
```

## Prerequisites

The prototype assumes a Linux host with:

* Docker / Docker Compose
* Rust and Cargo
* `bpf-linker`
* a pinned nightly Rust toolchain for the eBPF crate
* sudo access for loading eBPF programs

Install the pinned eBPF toolchain:

```bash
rustup toolchain install nightly-2026-06-02 --component rust-src
```

Install `bpf-linker` if needed:

```bash
cargo install bpf-linker
```

## Build

```bash
./scripts/build_all.sh
```

The userspace monitor build script builds the eBPF crate with the pinned nightly toolchain and BPF CPU v3, then embeds the resulting object into the userspace monitor.

The eBPF build uses target-specific BPF flags rather than global `RUSTFLAGS`, because BPF CPU levels such as `v3` must not be applied to normal host crates.

Useful overrides:

```bash
RUNTIME_MONITOR_EBPF_TOOLCHAIN=nightly-2026-06-02 ./scripts/build_all.sh
RUNTIME_MONITOR_EBPF_CPU=v3 ./scripts/build_all.sh
```

## Run manually

Start the FastAPI workload:

```bash
./scripts/run_workload.sh
```

Run the monitor:

```bash
sudo -v
sudo ./target/debug/runtime-monitor \
  --collector-config policies/fastapi-monitor-policy.json
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

* `/echo` produces `/usr/bin/echo` evidence and is accepted by policy.
* `/bad` produces `/usr/bin/id` evidence and is rejected by policy.

Stop the workload:

```bash
./scripts/stop_workload.sh
```

## Correctness tests

Fast Rust tests:

```bash
cargo test
```

Docker/sudo/eBPF integration smoke test:

```bash
sudo -v
./scripts/run_v1_integration_tests.py
```

The integration runner:

* builds the project,
* starts the Docker workload,
* creates per-case collector configs under `logs/integration/`,
* starts and stops the eBPF monitor per test case,
* checks fresh evidence was written,
* checks expected executable paths appear in evidence,
* runs the verifier,
* tears the workload down by default.

Current integration cases:

* `/echo` should produce `/usr/bin/echo` evidence and verifier `ACCEPT`.
* `/bad` should produce `/usr/bin/id` evidence and verifier `REJECT`.

Keep the workload running after tests:

```bash
KEEP_WORKLOAD=1 ./scripts/run_v1_integration_tests.py
```

## Performance and event-volume experiments

Performance experiments are separate from correctness tests because they are slower and noisier. They write JSON and CSV artefacts under `logs/experiments/`.

### Latency overhead

Compare baseline request latency against monitored request latency:

```bash
sudo -v
./scripts/run_performance_experiments.py \
  --experiment latency \
  --endpoint /echo \
  --requests 100 \
  --warmup 10 \
  --trials 5
```

This records baseline, monitored, and percentage overhead for:

* mean latency,
* median latency,
* p95 latency,
* min/max latency,
* approximate throughput.

Example thresholded run:

```bash
./scripts/run_performance_experiments.py \
  --experiment latency \
  --endpoint /echo \
  --requests 200 \
  --warmup 20 \
  --trials 5 \
  --max-overhead-pct 25
```

### Host-wide versus scoped event volume

Measure how much evidence volume is reduced by scoped collection:

```bash
sudo -v
./scripts/run_performance_experiments.py \
  --experiment event-volume \
  --endpoint /echo \
  --event-requests 20 \
  --event-duration-secs 10
```

The event-volume experiment:

* runs a host-wide capture,
* sends workload traffic,
* counts emitted JSONL events,
* records top executable paths,
* runs a scoped capture,
* sends the same workload traffic,
* computes absolute and percentage event-count reduction.

Run both latency and event-volume experiments:

```bash
./scripts/run_performance_experiments.py \
  --experiment both \
  --endpoint /echo \
  --requests 100 \
  --warmup 10 \
  --trials 5 \
  --event-requests 20 \
  --event-duration-secs 10
```

## Evidence summarisation

Summarise a specific evidence file:

```bash
./scripts/count_events.py logs/integration/runtime_events_echo.jsonl
```

Because evidence is now split across `logs/integration/` and `logs/experiments/`, pass the evidence path explicitly.

## Cleaning logs

Correctness-test artefacts are written under:

```text
logs/integration/
```

Experiment artefacts are written under:

```text
logs/experiments/
```

If using a cleanup script, it should clean both directories rather than assuming a single `logs/runtime_events.jsonl` file.

## Current claim

Workload-scoped eBPF exec evidence detects subprocess-style runtime deviations in a containerised FastAPI workload and reduces host-wide event noise while preserving workload-relevant events.

Current demonstrated behaviours:

* benign `/echo` execution is accepted;
* deviation `/bad` execution is rejected;
* scoped collection reduces irrelevant host-wide exec evidence;
* preliminary latency experiments can estimate monitored-versus-baseline overhead.

## Limitations

* Assumes a trusted kernel and monitor at monitor start.
* Detects exec-level deviations only.
* Pure Python `exec`/`eval` behaviour without subprocess creation is not detected.
* `argv`, `openat`, and `mmap` evidence are not yet covered.
* TPM PCR anchoring of runtime evidence is not yet implemented.
* Keylime integration is currently shallow composition rather than verifier/agent internals integration.
* Performance measurements are preliminary unless repeated under controlled release-build conditions with sufficient trials and workload diversity.
