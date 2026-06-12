# runtime-custodian

MEng FYP prototype for **Keylime-inspired workload-scoped runtime attestation**.

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

* **Keylime composition (design-level only)**

  * The intended end state is `ACCEPT = Keylime/IMA attestation AND runtime verification`, but this composition is **not implemented**: there is no Keylime or IMA code in this repository.
  * The runtime verifier deliberately mirrors Keylime's "replay the measurement log and check it against a TPM quote" pattern, so it is designed to compose with Keylime later. The integration itself is future work.

## Repository layout

```text
policies/                          # 9 collector configs and verifier policies
  fastapi-{monitor,verifier}-policy.json        # FastAPI single-workload config + policy
  binwalk-{monitor,verifier}-policy.json        # Binwalk workload config + policy
  multiworkload-fastapi-monitor-policy.json     # multi-workload collector config
  multiworkload-fastapi-{a,b}-verifier-policy.json  # per-workload policies
  runtime-policy-argv-sensitive-example.json    # argv-sensitive invocation example
  runtime-policy-policy-triggered-tpm.json      # TPM policy-triggered example

runtime-monitor/
  runtime-monitor-ebpf/            # no_std Aya eBPF program
  runtime-monitor/                 # userspace monitor/reporter + TPM wrapper (tpm.rs)
  runtime-verifier/                # runtime evidence verifier
  runtime-policy-trainer/          # draft-policy generation from a trusted run
  runtime-monitor-common/          # shared evidence, hashing, classification, IO

scripts/                           # ~19 scripts (build, workload, smoke tests, experiments)
  build_all.sh                     # builds workspace (release by default) + embedded eBPF object
  run_workload.sh / stop_workload.sh            # start/stop FastAPI Docker workload
  integration_lib.py               # shared Python test/experiment harness
  run_v1_integration_tests.py      # correctness smoke tests
  smoke_argv_policy_workflow.py    # argv-sensitive interpreter smoke test
  smoke_tpm_swtpm.sh / smoke_tpm_quote_swtpm.sh # software-TPM (swtpm) smoke tests
  run_performance_experiments.py   # latency and event-volume experiments
  run_binwalk_performance_experiments.py        # process-heavy wall-clock overhead
  run_concurrent_{fastapi,binwalk}_performance_experiments.py  # concurrent throughput
  run_security_experiments.py      # detection + tamper-evidence experiments
  run_verifier_scalability_experiments.py       # verifier replay cost

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
sudo ./target/release/runtime-monitor \
  --collector-config policies/fastapi-monitor-policy.json
```

Exercise benign and deviation paths:

```bash
curl -fsS http://127.0.0.1:8000/echo
curl -fsS http://127.0.0.1:8000/bad
```

Run the verifier:

```bash
./target/release/runtime-verifier \
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
* p99 latency,
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

Add controlled unrelated host activity when you want the scoped/host-wide
difference to be visible even on an otherwise quiet machine:

```bash
./scripts/run_performance_experiments.py \
  --experiment event-volume \
  --endpoint /echo \
  --event-requests 100 \
  --event-duration-secs 30 \
  --host-noise \
  --host-noise-workers 2
```

The JSON/CSV output includes runtime event count, synthetic record count, total
record count, evidence file size, and top executable paths for each mode.

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

### Binwalk wall-clock overhead

Binwalk is included as a process-heavy real-world command-line workload. The
container stays idle while the monitor is attached, then each trial executes a
fixed Binwalk command inside the container.

```bash
sudo -v
./scripts/run_binwalk_performance_experiments.py \
  --input zip.bin \
  --trials 5 \
  --binwalk-args "-e --run-as=root"
```

This writes one JSON file and one CSV file under `logs/experiments/` containing:

* baseline, scoped, and host-wide wall-clock runtime,
* scoped/host-wide evidence event counts,
* evidence byte size,
* verifier replay time for scoped evidence,
* classification counts and top executable paths.

Useful variants:

```bash
# Compare baseline against scoped only.
./scripts/run_binwalk_performance_experiments.py \
  --mode baseline \
  --mode scoped \
  --input yaffs2.bin \
  --trials 3

# Include argv capture cost in the monitored runs.
./scripts/run_binwalk_performance_experiments.py \
  --input zip.bin \
  --trials 5 \
  --capture-argv
```


### Concurrent FastAPI throughput

For a true concurrent service benchmark, run several FastAPI containers and send
requests to them in parallel. This stresses multi-workload cgroup binding and
reports aggregate throughput rather than only sequential request latency.

```bash
sudo -v
./scripts/run_concurrent_fastapi_performance_experiments.py \
  --containers 4 \
  --requests-per-container 200 \
  --warmup-per-container 20 \
  --concurrency 16 \
  --endpoint /echo \
  --trials 5
```

The script creates containers named `fastapi-concurrent-1`,
`fastapi-concurrent-2`, and so on, writes a multi-workload collector config, and
compares `baseline`, `scoped`, and `host-wide` modes. JSON/CSV output includes
per-request latency, total batch wall-clock time, requests/second, evidence size,
runtime event counts, per-workload event counts, and verifier replay time for
scoped evidence.

Useful variants:

```bash
# Measure monitor cost when the service does not spawn subprocesses.
./scripts/run_concurrent_fastapi_performance_experiments.py \
  --containers 4 \
  --requests-per-container 500 \
  --concurrency 32 \
  --endpoint /ping \
  --skip-evidence-check

# Compare only baseline and scoped if time is short.
./scripts/run_concurrent_fastapi_performance_experiments.py \
  --mode baseline \
  --mode scoped \
  --containers 4 \
  --requests-per-container 200 \
  --concurrency 16 \
  --endpoint /echo \
  --trials 3
```

### Concurrent Binwalk throughput

For the strongest stress test, run several Binwalk containers concurrently. This
creates parallel process-heavy workload activity and exercises the collector's
multi-workload map, ring-buffer handling, evidence writer, policy classifier, and
verifier replay under higher event pressure.

```bash
sudo -v
./scripts/run_concurrent_binwalk_performance_experiments.py \
  --containers 4 \
  --runs-per-container 1 \
  --concurrency 4 \
  --input zip.bin \
  --trials 5
```

The script builds the Binwalk image, starts containers named
`binwalk-concurrent-1`, `binwalk-concurrent-2`, and so on, writes a
multi-workload collector config, and compares `baseline`, `scoped`, and
`host-wide` modes. JSON/CSV output includes total concurrent batch wall-clock
time, per-run wall-clock time, completed Binwalk runs per second, event counts,
evidence byte size, per-workload event counts, and scoped verifier replay time.

Useful variants:

```bash
# Short smoke run before collecting final report data.
./scripts/run_concurrent_binwalk_performance_experiments.py \
  --mode baseline \
  --mode scoped \
  --containers 2 \
  --runs-per-container 1 \
  --concurrency 2 \
  --input zip.bin \
  --trials 1 \
  --no-build

# Assign several samples round-robin across containers.
./scripts/run_concurrent_binwalk_performance_experiments.py \
  --containers 6 \
  --runs-per-container 1 \
  --concurrency 6 \
  --input zip.bin \
  --input bzip2.bin \
  --input yaffs2.bin \
  --trials 3

# Include argv capture cost in the concurrent process-heavy run.
./scripts/run_concurrent_binwalk_performance_experiments.py \
  --containers 4 \
  --runs-per-container 1 \
  --concurrency 4 \
  --input zip.bin \
  --trials 5 \
  --capture-argv
```

### Verifier replay scalability

After generating one or more evidence logs, measure replay cost separately:

```bash
./scripts/run_verifier_scalability_experiments.py \
  --iterations 10 \
  --case fastapi_echo:policies/fastapi-verifier-policy.json:logs/experiments/runtime_events_fastapi_echo_scoped.jsonl:logs/experiments/runtime_events_fastapi_echo_scoped.summary.json \
  --case binwalk:policies/binwalk-verifier-policy.json:logs/experiments/runtime_events_binwalk_perf_scoped_trial_1.jsonl:logs/experiments/runtime_events_binwalk_perf_scoped_trial_1.summary.json
```

Each case records runtime event count, synthetic record count, evidence size, and
verifier wall-clock time. This is the data to use for the report's verifier
scalability table.

## Evidence summarisation

Summarise a specific evidence file:

```bash
./scripts/summarise_events.py logs/integration/runtime_events_echo.jsonl
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
* interpreter invocations are captured with bounded `argv` and checked against an allowed-invocation policy, so a known-good `python` command is accepted while an unexpected one is flagged;
* the verifier independently replays the evidence log and rejects edited, reordered, or deleted records as invalid evidence;
* suspicious and denied events are extended into a TPM PCR online (software/swtpm), and the verifier reconstructs the expected PCR and verifies the quote;
* multiple workloads are monitored in a single session, each classified against its own policy;
* scoped collection reduces irrelevant host-wide exec evidence;
* preliminary latency experiments can estimate monitored-versus-baseline overhead.

## Limitations

* Assumes a trusted kernel and monitor at monitor start.
* Detects exec-level deviations only.
* Pure Python `exec`/`eval` behaviour without subprocess creation is not detected.
* `openat` and `mmap` evidence are not yet covered. (Bounded `argv` capture for interpreter invocations *is* implemented, via the `sys_enter_execve` tracepoint.)
* TPM PCR anchoring is implemented as a software/swtpm prototype (session-start, policy-triggered per-event, and final-summary PCR extends, plus an offline nonce-bound quote). It is not yet rooted in a hardware/CVM measured-boot anchor, and the quote path performs no AK/EK certification or live remote challenge.
* Keylime/IMA integration is **not implemented** (design-level only): the runtime verifier is designed to compose with Keylime, but no Keylime or IMA code exists in this repository yet.
* Performance measurements are preliminary unless repeated under controlled release-build conditions with sufficient trials and workload diversity.
