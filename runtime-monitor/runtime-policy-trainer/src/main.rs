use anyhow::{Result, anyhow};
use runtime_monitor_common::{
    AcceptablePolicy, AttestationPolicy, DeniedPolicy, EvidenceRecord, RuntimeEvent, RuntimePolicy,
    RuntimeSummary, SuspiciousPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

const CANDIDATE_POLICY_WARNING: &str =
    "Candidate policy generated from trusted baseline sessions; review before enforcement.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    evidence: Vec<PathBuf>,
    summaries: Vec<PathBuf>,
    workload_id: Option<String>,
    out: PathBuf,
    metadata_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrainingMetadata {
    warning: String,
    input_evidence_paths: Vec<String>,
    input_summary_paths: Vec<String>,
    sessions_used: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload_id_filter: Option<String>,
    total_runtime_event_count: u64,
    skipped_empty_exe_path_count: u64,
    observed_executable_counts: BTreeMap<String, u64>,
    observed_comm_counts: BTreeMap<String, u64>,
    observed_event_type_counts: BTreeMap<String, u64>,
    generated_acceptable_exec_paths: Vec<String>,
    generated_acceptable_event_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrainingOutput {
    policy: RuntimePolicy,
    metadata: TrainingMetadata,
}

fn parse_args_from<I, S>(args: I) -> Result<Args>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut evidence = Vec::new();
    let mut summaries = Vec::new();
    let mut workload_id = None;
    let mut out = None;
    let mut metadata_out = None;
    let mut args = args.into_iter().map(Into::into);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--evidence" => evidence.push(next_path(&mut args, "--evidence")?),
            "--summary" => summaries.push(next_path(&mut args, "--summary")?),
            "--workload-id" => {
                workload_id = Some(next_value(&mut args, "--workload-id")?);
            }
            "--out" => out = Some(next_path(&mut args, "--out")?),
            "--metadata-out" => metadata_out = Some(next_path(&mut args, "--metadata-out")?),
            _ => {
                return Err(anyhow!(
                    "unknown argument `{arg}`; usage: runtime-policy-trainer --evidence <runtime_events.jsonl> --summary <runtime_summary.json> [--evidence ... --summary ...] [--workload-id <id>] --out <runtime_policy.json> [--metadata-out <training.json>]"
                ));
            }
        }
    }

    if evidence.is_empty() {
        return Err(anyhow!("at least one --evidence path is required"));
    }
    if summaries.is_empty() {
        return Err(anyhow!("at least one --summary path is required"));
    }
    if evidence.len() != summaries.len() {
        return Err(anyhow!(
            "--evidence and --summary must be provided the same number of times; got {} evidence path(s) and {} summary path(s)",
            evidence.len(),
            summaries.len()
        ));
    }

    Ok(Args {
        evidence,
        summaries,
        workload_id,
        out: out.ok_or_else(|| anyhow!("missing required --out <runtime_policy.json>"))?,
        metadata_out,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("{flag} requires a non-empty value"))
}

fn next_path(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(next_value(args, flag)?))
}

fn train_from_paths(args: &Args) -> Result<TrainingOutput> {
    let mut learner = PolicyLearner::new(args.workload_id.clone());
    let mut sessions_used = BTreeSet::new();
    let mut summary_workload_ids = BTreeSet::new();

    for (evidence_path, summary_path) in args.evidence.iter().zip(&args.summaries) {
        let summary = load_json::<RuntimeSummary>(summary_path, "runtime summary")?;
        if !summary.workload_id.trim().is_empty() {
            summary_workload_ids.insert(summary.workload_id.clone());
        }
        sessions_used.insert(summary.session_id.clone());

        let records = load_evidence_records(evidence_path)?;
        let mut parsed_runtime_events = 0u64;

        for record in &records {
            let record_session_id = record_session_id(record);
            if record_session_id != summary.session_id {
                return Err(anyhow!(
                    "session_id mismatch in evidence {}: expected summary session_id {} got {}",
                    evidence_path.display(),
                    summary.session_id,
                    record_session_id
                ));
            }

            if let EvidenceRecord::RuntimeEvent(event) = record {
                parsed_runtime_events += 1;
                learner.observe_runtime_event(&event.event);
            }
        }

        if parsed_runtime_events != summary.event_count {
            return Err(anyhow!(
                "runtime event count mismatch for evidence {} and summary {}: parsed {} runtime event(s), summary.event_count is {}",
                evidence_path.display(),
                summary_path.display(),
                parsed_runtime_events,
                summary.event_count
            ));
        }
    }

    learner.finish(
        &args.evidence,
        &args.summaries,
        sessions_used,
        summary_workload_ids,
    )
}

#[derive(Debug, Clone)]
struct PolicyLearner {
    workload_id_filter: Option<String>,
    total_runtime_event_count: u64,
    skipped_empty_exe_path_count: u64,
    observed_executable_counts: BTreeMap<String, u64>,
    observed_comm_counts: BTreeMap<String, u64>,
    observed_event_type_counts: BTreeMap<String, u64>,
    learned_workload_ids: BTreeSet<String>,
}

impl PolicyLearner {
    fn new(workload_id_filter: Option<String>) -> Self {
        Self {
            workload_id_filter,
            total_runtime_event_count: 0,
            skipped_empty_exe_path_count: 0,
            observed_executable_counts: BTreeMap::new(),
            observed_comm_counts: BTreeMap::new(),
            observed_event_type_counts: BTreeMap::new(),
            learned_workload_ids: BTreeSet::new(),
        }
    }

    fn observe_runtime_event(&mut self, event: &RuntimeEvent) {
        if let Some(filter) = self.workload_id_filter.as_deref()
            && event.workload_id.as_deref() != Some(filter)
        {
            return;
        }

        self.total_runtime_event_count += 1;
        if let Some(workload_id) = event
            .workload_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.learned_workload_ids.insert(workload_id.to_owned());
        }

        increment_count(
            &mut self.observed_event_type_counts,
            event.event_type.policy_name(),
        );
        increment_count(&mut self.observed_comm_counts, event.comm.clone());

        let exe_path = event.exe_path.trim();
        if exe_path.is_empty() {
            self.skipped_empty_exe_path_count += 1;
        } else {
            increment_count(&mut self.observed_executable_counts, exe_path.to_owned());
        }
    }

    fn finish(
        self,
        evidence_paths: &[PathBuf],
        summary_paths: &[PathBuf],
        sessions_used: BTreeSet<String>,
        summary_workload_ids: BTreeSet<String>,
    ) -> Result<TrainingOutput> {
        if self.total_runtime_event_count == 0 {
            return Err(anyhow!(
                "no runtime events matched the training inputs; pass --workload-id for a workload present in the evidence or provide non-empty evidence"
            ));
        }

        if self.observed_executable_counts.is_empty() {
            return Err(anyhow!(
                "no non-empty executable paths were observed after filtering; cannot generate acceptable.exec_paths"
            ));
        }

        let workload_id = match self.workload_id_filter.clone() {
            Some(workload_id) => workload_id,
            None if self.learned_workload_ids.len() == 1 => self
                .learned_workload_ids
                .iter()
                .next()
                .cloned()
                .expect("one"),
            None if self.learned_workload_ids.len() > 1 => {
                return Err(anyhow!(
                    "multiple workload IDs were observed in training evidence: {}; pass --workload-id to train one workload",
                    self.learned_workload_ids
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            None if summary_workload_ids.len() == 1 => {
                summary_workload_ids.iter().next().cloned().expect("one")
            }
            None => {
                return Err(anyhow!(
                    "could not infer a single workload_id from learned runtime events; pass --workload-id"
                ));
            }
        };

        let generated_acceptable_exec_paths: Vec<String> =
            self.observed_executable_counts.keys().cloned().collect();
        let generated_acceptable_event_types: Vec<String> =
            self.observed_event_type_counts.keys().cloned().collect();

        let policy = RuntimePolicy {
            workload_id,
            acceptable: AcceptablePolicy {
                exec_paths: generated_acceptable_exec_paths.clone(),
                event_types: generated_acceptable_event_types.clone(),
            },
            suspicious: SuspiciousPolicy {
                unknown_exec_path: true,
            },
            denied: DeniedPolicy {
                exec_paths: Vec::new(),
                comm_names: Vec::new(),
            },
            attestation: AttestationPolicy::default(),
            ..RuntimePolicy::default()
        };

        let metadata = TrainingMetadata {
            warning: String::from(CANDIDATE_POLICY_WARNING),
            input_evidence_paths: paths_to_strings(evidence_paths),
            input_summary_paths: paths_to_strings(summary_paths),
            sessions_used: sessions_used.into_iter().collect(),
            workload_id_filter: self.workload_id_filter,
            total_runtime_event_count: self.total_runtime_event_count,
            skipped_empty_exe_path_count: self.skipped_empty_exe_path_count,
            observed_executable_counts: self.observed_executable_counts,
            observed_comm_counts: self.observed_comm_counts,
            observed_event_type_counts: self.observed_event_type_counts,
            generated_acceptable_exec_paths,
            generated_acceptable_event_types,
        };

        Ok(TrainingOutput { policy, metadata })
    }
}

fn increment_count(counts: &mut BTreeMap<String, u64>, value: String) {
    *counts.entry(value).or_insert(0) += 1;
}

fn paths_to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

fn load_json<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let file =
        File::open(path).map_err(|e| anyhow!("failed to open {label} {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse {label} {}: {e}", path.display()))
}

fn load_evidence_records(path: &Path) -> Result<Vec<EvidenceRecord>> {
    let file =
        File::open(path).map_err(|e| anyhow!("failed to open evidence {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut line = String::new();
    let mut line_no = 0usize;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|e| {
            anyhow!(
                "failed to read evidence {} at line {}: {e}",
                path.display(),
                line_no + 1
            )
        })?;
        if bytes_read == 0 {
            break;
        }
        line_no += 1;

        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str::<EvidenceRecord>(&line).map_err(|e| {
            anyhow!(
                "failed to parse evidence {} at line {}: {e}",
                path.display(),
                line_no
            )
        })?;
        records.push(record);
    }

    Ok(records)
}

fn record_session_id(record: &EvidenceRecord) -> &str {
    match record {
        EvidenceRecord::RuntimeEvent(event) => &event.session_id,
        EvidenceRecord::Synthetic(record) => &record.session_id,
    }
}

fn write_json_pretty<T>(path: &Path, value: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "failed to create {label} directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let file = File::create(path)
        .map_err(|e| anyhow!("failed to create {label} {}: {e}", path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)
        .map_err(|e| anyhow!("failed to write {label} {}: {e}", path.display()))
}

fn implicit_metadata_path(policy_out: &Path) -> PathBuf {
    let mut path = policy_out.to_path_buf();
    path.set_extension("training.json");
    path
}

fn run(args: Args) -> Result<()> {
    let output = train_from_paths(&args)?;
    write_json_pretty(&args.out, &output.policy, "generated runtime policy")?;

    match args.metadata_out.as_ref() {
        Some(metadata_out) => {
            write_json_pretty(metadata_out, &output.metadata, "training metadata")?
        }
        None => {
            let metadata_out = implicit_metadata_path(&args.out);
            if let Err(error) =
                write_json_pretty(&metadata_out, &output.metadata, "training metadata")
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "warning: generated policy {}, but failed to write optional training metadata {}: {error}",
                    args.out.display(),
                    metadata_out.display()
                );
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    run(parse_args_from(std::env::args().skip(1))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_monitor_common::evidence::RuntimeEventType;
    use runtime_monitor_common::{
        EventClassification, EvidenceEvent, EvidenceSyntheticRecord, SyntheticRecordType,
    };

    const SESSION_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SESSION_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Debug)]
    struct TestFiles {
        dir: PathBuf,
        evidence: PathBuf,
        summary: PathBuf,
    }

    impl TestFiles {
        fn new(name: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "runtime-policy-trainer-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("test dir");
            Self {
                evidence: dir.join("runtime_events.jsonl"),
                summary: dir.join("runtime_summary.json"),
                dir,
            }
        }

        fn write(&self, session_id: &str, records: &[EvidenceRecord], event_count: u64) {
            write_records(&self.evidence, records);
            write_json_pretty(
                &self.summary,
                &summary(
                    session_id,
                    "workload-a",
                    event_count,
                    synthetic_count(records),
                ),
                "test summary",
            )
            .expect("summary");
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn runtime_record(
        session_id: &str,
        seq_no: u64,
        workload_id: Option<&str>,
        exe_path: &str,
        event_type: RuntimeEventType,
        comm: &str,
    ) -> EvidenceRecord {
        EvidenceRecord::RuntimeEvent(EvidenceEvent {
            session_id: session_id.to_owned(),
            seq_no,
            event: RuntimeEvent {
                workload_index: 0,
                workload_id: workload_id.map(str::to_owned),
                event_type,
                timestamp_ns: 42,
                cgroup_id: 99,
                pid: 123,
                tgid: 123,
                ppid: 1,
                cpu: 2,
                comm: comm.to_owned(),
                exe_path: exe_path.to_owned(),
            },
            classification: EventClassification::Acceptable,
            rule_id: String::from("test"),
            reason: String::from("test"),
            event_hash: String::from("hash"),
            software_chain_head: String::from("chain"),
            tpm_extended: false,
            tpm_extend_index: None,
        })
    }

    fn synthetic_record(session_id: &str, seq_no: u64) -> EvidenceRecord {
        EvidenceRecord::Synthetic(EvidenceSyntheticRecord {
            session_id: session_id.to_owned(),
            seq_no,
            record_type: SyntheticRecordType::MonitorStart,
            reason: String::from("test"),
            record_hash: String::from("hash"),
            software_chain_head: String::from("chain"),
        })
    }

    fn summary(
        session_id: &str,
        workload_id: &str,
        event_count: u64,
        synthetic_record_count: u64,
    ) -> RuntimeSummary {
        RuntimeSummary {
            schema_version: 1,
            session_id: session_id.to_owned(),
            workload_id: workload_id.to_owned(),
            collection_mode: String::from("scoped"),
            policy_hash: String::from("policy"),
            monitor_config_hash: None,
            attestation_status: String::from("passed"),
            failure_reason: None,
            event_count,
            synthetic_record_count,
            acceptable_count: event_count,
            suspicious_count: 0,
            denied_count: 0,
            dropped_events: 0,
            software_chain_head: String::from("chain"),
            final_summary_digest: None,
            tpm: None,
        }
    }

    fn synthetic_count(records: &[EvidenceRecord]) -> u64 {
        records
            .iter()
            .filter(|record| matches!(record, EvidenceRecord::Synthetic(_)))
            .count() as u64
    }

    fn write_records(path: &Path, records: &[EvidenceRecord]) {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).expect("records parent");
        }
        let mut file = File::create(path).expect("records");
        for record in records {
            serde_json::to_writer(&mut file, record).expect("record");
            writeln!(file).expect("newline");
        }
    }

    fn train(files: &[&TestFiles], workload_id: Option<&str>) -> TrainingOutput {
        let args = Args {
            evidence: files.iter().map(|files| files.evidence.clone()).collect(),
            summaries: files.iter().map(|files| files.summary.clone()).collect(),
            workload_id: workload_id.map(str::to_owned),
            out: files[0].dir.join("policy.json"),
            metadata_out: None,
        };
        train_from_paths(&args).expect("training")
    }

    fn assert_policy_round_trips(policy: &RuntimePolicy) {
        let json = serde_json::to_string(policy).expect("policy json");
        serde_json::from_str::<RuntimePolicy>(&json).expect("runtime policy");
    }

    #[test]
    fn generates_policy_from_one_evidence_file() {
        let files = TestFiles::new("one-file");
        files.write(
            SESSION_A,
            &[
                synthetic_record(SESSION_A, 1),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
            ],
            1,
        );

        let output = train(&[&files], None);

        assert_eq!(output.policy.workload_id, "workload-a");
        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert_eq!(output.policy.acceptable.event_types, vec!["exec"]);
        assert_policy_round_trips(&output.policy);
    }

    #[test]
    fn merges_multiple_evidence_files() {
        let left = TestFiles::new("merge-left");
        left.write(
            SESSION_A,
            &[runtime_record(
                SESSION_A,
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                RuntimeEventType::Exec,
                "echo",
            )],
            1,
        );
        let right = TestFiles::new("merge-right");
        right.write(
            SESSION_B,
            &[runtime_record(
                SESSION_B,
                1,
                Some("workload-a"),
                "/usr/bin/python",
                RuntimeEventType::Fork,
                "python",
            )],
            1,
        );

        let output = train(&[&left, &right], None);

        assert_eq!(
            output.policy.acceptable.exec_paths,
            vec!["/usr/bin/echo", "/usr/bin/python"]
        );
        assert_eq!(output.policy.acceptable.event_types, vec!["exec", "fork"]);
        assert_eq!(output.metadata.sessions_used, vec![SESSION_A, SESSION_B]);
    }

    #[test]
    fn ignores_synthetic_records_for_learning() {
        let files = TestFiles::new("synthetic");
        files.write(
            SESSION_A,
            &[
                synthetic_record(SESSION_A, 1),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
                synthetic_record(SESSION_A, 3),
            ],
            1,
        );

        let output = train(&[&files], None);

        assert_eq!(output.metadata.total_runtime_event_count, 1);
        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
    }

    #[test]
    fn filters_by_workload_id() {
        let files = TestFiles::new("filter");
        files.write(
            SESSION_A,
            &[
                runtime_record(
                    SESSION_A,
                    1,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-b"),
                    "/usr/bin/id",
                    RuntimeEventType::Exec,
                    "id",
                ),
            ],
            2,
        );

        let output = train(&[&files], Some("workload-a"));

        assert_eq!(output.policy.workload_id, "workload-a");
        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert_eq!(output.metadata.total_runtime_event_count, 1);
        assert_eq!(
            output.metadata.workload_id_filter.as_deref(),
            Some("workload-a")
        );
    }

    #[test]
    fn errors_when_summary_session_id_does_not_match_records() {
        let files = TestFiles::new("session-mismatch");
        files.write(
            SESSION_A,
            &[runtime_record(
                SESSION_B,
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                RuntimeEventType::Exec,
                "echo",
            )],
            1,
        );

        let error = train_from_paths(&Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: files.dir.join("policy.json"),
            metadata_out: None,
        })
        .expect_err("session mismatch");

        assert!(error.to_string().contains("session_id mismatch"));
    }

    #[test]
    fn errors_when_summary_event_count_does_not_match_runtime_records() {
        let files = TestFiles::new("count-mismatch");
        files.write(
            SESSION_A,
            &[runtime_record(
                SESSION_A,
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                RuntimeEventType::Exec,
                "echo",
            )],
            2,
        );

        let error = train_from_paths(&Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: files.dir.join("policy.json"),
            metadata_out: None,
        })
        .expect_err("event count mismatch");

        assert!(error.to_string().contains("event count mismatch"));
    }

    #[test]
    fn output_exec_paths_are_sorted_and_deduplicated() {
        let files = TestFiles::new("sorted");
        files.write(
            SESSION_A,
            &[
                runtime_record(
                    SESSION_A,
                    1,
                    Some("workload-a"),
                    "/usr/bin/python",
                    RuntimeEventType::Exec,
                    "python",
                ),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
                runtime_record(
                    SESSION_A,
                    3,
                    Some("workload-a"),
                    "/usr/bin/python",
                    RuntimeEventType::Fork,
                    "python",
                ),
            ],
            3,
        );

        let output = train(&[&files], None);

        assert_eq!(
            output.policy.acceptable.exec_paths,
            vec!["/usr/bin/echo", "/usr/bin/python"]
        );
        assert_eq!(output.policy.acceptable.event_types, vec!["exec", "fork"]);
    }

    #[test]
    fn generated_policy_leaves_denied_lists_empty_and_warning_policy_enabled() {
        let files = TestFiles::new("denied-empty");
        files.write(
            SESSION_A,
            &[runtime_record(
                SESSION_A,
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                RuntimeEventType::Exec,
                "echo",
            )],
            1,
        );

        let output = train(&[&files], None);

        assert!(output.policy.denied.exec_paths.is_empty());
        assert!(output.policy.denied.comm_names.is_empty());
        assert!(output.policy.suspicious.unknown_exec_path);
        assert!(!output.policy.attestation.fail_on_suspicious);
        assert!(output.policy.attestation.fail_on_denied);
        assert!(output.policy.attestation.fail_on_drops);
        assert_eq!(output.policy.attestation.backend, "none");
        assert_eq!(output.policy.attestation.mode, "software-chain");
    }

    #[test]
    fn multiple_learned_workload_ids_require_filter() {
        let files = TestFiles::new("multiple-workloads");
        files.write(
            SESSION_A,
            &[
                runtime_record(
                    SESSION_A,
                    1,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-b"),
                    "/usr/bin/id",
                    RuntimeEventType::Exec,
                    "id",
                ),
            ],
            2,
        );

        let error = train_from_paths(&Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: files.dir.join("policy.json"),
            metadata_out: None,
        })
        .expect_err("multiple workloads");

        assert!(error.to_string().contains("multiple workload IDs"));
        assert!(error.to_string().contains("--workload-id"));
    }

    #[test]
    fn skips_empty_exe_paths_and_records_metadata_count() {
        let files = TestFiles::new("empty-path");
        files.write(
            SESSION_A,
            &[
                runtime_record(
                    SESSION_A,
                    1,
                    Some("workload-a"),
                    "",
                    RuntimeEventType::Exec,
                    "empty",
                ),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
            ],
            2,
        );

        let output = train(&[&files], None);

        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert_eq!(output.metadata.skipped_empty_exe_path_count, 1);
        assert!(!output.metadata.observed_executable_counts.contains_key(""));
    }

    #[test]
    fn errors_when_no_non_empty_executable_paths_remain() {
        let files = TestFiles::new("only-empty-paths");
        files.write(
            SESSION_A,
            &[runtime_record(
                SESSION_A,
                1,
                Some("workload-a"),
                "",
                RuntimeEventType::Exec,
                "empty",
            )],
            1,
        );

        let error = train_from_paths(&Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: files.dir.join("policy.json"),
            metadata_out: None,
        })
        .expect_err("no executable paths");

        assert!(error.to_string().contains("no non-empty executable paths"));
    }

    #[test]
    fn sidecar_contains_deterministic_counts_and_allowlists() {
        let files = TestFiles::new("sidecar");
        files.write(
            SESSION_A,
            &[
                runtime_record(
                    SESSION_A,
                    1,
                    Some("workload-a"),
                    "/usr/bin/python",
                    RuntimeEventType::Exec,
                    "python",
                ),
                runtime_record(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/bin/python",
                    RuntimeEventType::Fork,
                    "python",
                ),
                runtime_record(
                    SESSION_A,
                    3,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    RuntimeEventType::Exec,
                    "echo",
                ),
            ],
            3,
        );

        let output = train(&[&files], None);

        assert_eq!(
            output.metadata.observed_executable_counts["/usr/bin/python"],
            2
        );
        assert_eq!(output.metadata.observed_comm_counts["python"], 2);
        assert_eq!(output.metadata.observed_event_type_counts["exec"], 2);
        assert_eq!(
            output.metadata.generated_acceptable_exec_paths,
            vec!["/usr/bin/echo", "/usr/bin/python"]
        );
        assert_eq!(
            output.metadata.generated_acceptable_event_types,
            vec!["exec", "fork"]
        );
        assert!(output.metadata.warning.contains("Candidate policy"));
    }

    #[test]
    fn explicit_metadata_failure_is_fatal_but_implicit_failure_is_nonfatal() {
        let files = TestFiles::new("metadata-failure");
        files.write(
            SESSION_A,
            &[runtime_record(
                SESSION_A,
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                RuntimeEventType::Exec,
                "echo",
            )],
            1,
        );
        let out = files.dir.join("policy.json");
        let blocked_metadata = files.dir.join("policy.training.json");
        fs::create_dir_all(&blocked_metadata).expect("blocked metadata dir");

        run(Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: out.clone(),
            metadata_out: None,
        })
        .expect("implicit metadata failure should not fail");
        assert!(out.exists());

        let explicit_error = run(Args {
            evidence: vec![files.evidence.clone()],
            summaries: vec![files.summary.clone()],
            workload_id: None,
            out: files.dir.join("policy-explicit.json"),
            metadata_out: Some(blocked_metadata),
        })
        .expect_err("explicit metadata failure");

        assert!(explicit_error.to_string().contains("training metadata"));
    }
}
