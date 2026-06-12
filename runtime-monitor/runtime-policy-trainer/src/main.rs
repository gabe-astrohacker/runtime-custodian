use anyhow::{Result, anyhow};
use runtime_monitor_common::evidence::RuntimeEventType;
use runtime_monitor_common::{
    AcceptableInvocationPolicy, AcceptablePolicy, AttestationPolicy, DeniedPolicy, EvidenceRecord,
    InvocationMatchType, RuntimeEvent, RuntimePolicy, RuntimeSummary, SuspiciousPolicy,
    load_evidence_records, load_json, record_session_id, write_json_pretty,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::fs::{self, File};
use std::io::Write;
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
    skipped_incomplete_argv_invocation_count: u64,
    observed_executable_counts: BTreeMap<String, u64>,
    observed_comm_counts: BTreeMap<String, u64>,
    observed_event_type_counts: BTreeMap<String, u64>,
    observed_exec_attempt_invocations: Vec<ObservedInvocation>,
    observed_interpreter_invocations: Vec<ObservedInvocation>,
    generated_acceptable_exec_paths: Vec<String>,
    generated_acceptable_event_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ObservedInvocation {
    exe_path: String,
    argv: Vec<String>,
    count: u64,
    sessions_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload_id: Option<String>,
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
                learner.observe_runtime_event(&event.event, &summary.session_id);
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
    skipped_incomplete_argv_invocation_count: u64,
    observed_executable_counts: BTreeMap<String, u64>,
    observed_successful_exec_counts: BTreeMap<String, u64>,
    observed_comm_counts: BTreeMap<String, u64>,
    observed_event_type_counts: BTreeMap<String, u64>,
    observed_exec_attempt_invocations: BTreeMap<InvocationKey, InvocationStats>,
    learned_workload_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InvocationKey {
    workload_id: Option<String>,
    exe_path: String,
    argv: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct InvocationStats {
    count: u64,
    sessions_seen: BTreeSet<String>,
}

impl PolicyLearner {
    fn new(workload_id_filter: Option<String>) -> Self {
        Self {
            workload_id_filter,
            total_runtime_event_count: 0,
            skipped_empty_exe_path_count: 0,
            skipped_incomplete_argv_invocation_count: 0,
            observed_executable_counts: BTreeMap::new(),
            observed_successful_exec_counts: BTreeMap::new(),
            observed_comm_counts: BTreeMap::new(),
            observed_event_type_counts: BTreeMap::new(),
            observed_exec_attempt_invocations: BTreeMap::new(),
            learned_workload_ids: BTreeSet::new(),
        }
    }

    fn observe_runtime_event(&mut self, event: &RuntimeEvent, session_id: &str) {
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

        match event.event_type {
            RuntimeEventType::Exec => {
                if !exe_path.is_empty() {
                    increment_count(
                        &mut self.observed_successful_exec_counts,
                        exe_path.to_owned(),
                    );
                }
            }
            RuntimeEventType::ExecAttempt => {
                self.observe_exec_attempt_invocation(event, session_id);
            }
            RuntimeEventType::Fork | RuntimeEventType::Unknown(_) => {}
        }
    }

    fn observe_exec_attempt_invocation(&mut self, event: &RuntimeEvent, session_id: &str) {
        if !argv_evidence_complete_for_invocation_training(event) {
            self.skipped_incomplete_argv_invocation_count += 1;
            return;
        }

        let key = InvocationKey {
            workload_id: event
                .workload_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            exe_path: event.exe_path.trim().to_owned(),
            argv: event.argv.clone(),
        };
        let stats = self
            .observed_exec_attempt_invocations
            .entry(key)
            .or_default();
        stats.count += 1;
        stats.sessions_seen.insert(session_id.to_owned());
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

        if self.observed_successful_exec_counts.is_empty() {
            return Err(anyhow!(
                "no non-empty successful exec paths were observed after filtering; cannot generate acceptable.exec_paths"
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

        let generated_acceptable_exec_paths: Vec<String> = self
            .observed_successful_exec_counts
            .keys()
            .cloned()
            .collect();
        let generated_acceptable_event_types: Vec<String> = self
            .observed_event_type_counts
            .keys()
            .filter(|event_type| event_type.as_str() != "exec-attempt")
            .cloned()
            .collect();
        let observed_exec_attempt_invocations =
            invocation_map_to_metadata(&self.observed_exec_attempt_invocations);
        let observed_interpreter_invocations: Vec<ObservedInvocation> =
            observed_exec_attempt_invocations
                .iter()
                .filter(|invocation| is_interpreter_invocation(invocation))
                .cloned()
                .collect();
        let (argv_sensitive_exec_paths, allowed_invocations) =
            argv_sensitive_policy_from_invocations(&observed_interpreter_invocations);

        let policy = RuntimePolicy {
            workload_id,
            acceptable: AcceptablePolicy {
                exec_paths: generated_acceptable_exec_paths.clone(),
                event_types: generated_acceptable_event_types.clone(),
                argv_sensitive_exec_paths,
                allowed_invocations,
                ..AcceptablePolicy::default()
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
            skipped_incomplete_argv_invocation_count: self.skipped_incomplete_argv_invocation_count,
            observed_executable_counts: self.observed_executable_counts,
            observed_comm_counts: self.observed_comm_counts,
            observed_event_type_counts: self.observed_event_type_counts,
            observed_exec_attempt_invocations,
            observed_interpreter_invocations,
            generated_acceptable_exec_paths,
            generated_acceptable_event_types,
        };

        Ok(TrainingOutput { policy, metadata })
    }
}

fn invocation_map_to_metadata(
    invocations: &BTreeMap<InvocationKey, InvocationStats>,
) -> Vec<ObservedInvocation> {
    invocations
        .iter()
        .map(|(key, stats)| ObservedInvocation {
            exe_path: key.exe_path.clone(),
            argv: key.argv.clone(),
            count: stats.count,
            sessions_seen: stats.sessions_seen.len() as u64,
            workload_id: key.workload_id.clone(),
        })
        .collect()
}

fn is_interpreter_invocation(invocation: &ObservedInvocation) -> bool {
    let exe_path = invocation.exe_path.trim();
    if is_interpreter_basename(path_basename(exe_path)) {
        return true;
    }

    if exe_path_is_non_informative(exe_path)
        && let Some(argv0) = invocation.argv.first()
    {
        return is_interpreter_basename(path_basename(argv0.trim()));
    }

    false
}

fn argv_sensitive_policy_from_invocations(
    invocations: &[ObservedInvocation],
) -> (Vec<String>, Vec<AcceptableInvocationPolicy>) {
    let mut argv_sensitive_exec_paths = BTreeSet::new();
    let mut allowed_invocations = Vec::new();

    for invocation in invocations {
        let exe_path = invocation.exe_path.trim();
        if exe_path_is_non_informative(exe_path) {
            continue;
        }

        argv_sensitive_exec_paths.insert(exe_path.to_owned());
        allowed_invocations.push(AcceptableInvocationPolicy {
            exe_path: exe_path.to_owned(),
            argv: invocation.argv.clone(),
            match_type: InvocationMatchType::Exact,
        });
    }

    allowed_invocations.sort_unstable();
    (
        argv_sensitive_exec_paths.into_iter().collect(),
        allowed_invocations,
    )
}

fn argv_evidence_complete_for_invocation_training(event: &RuntimeEvent) -> bool {
    event.argv_complete
        && !event.argv_truncated
        && !event.argv_read_error
        && !event.filename_truncated
        && !event.filename_read_error
}

fn exe_path_is_non_informative(exe_path: &str) -> bool {
    exe_path.is_empty() || !Path::new(exe_path).is_absolute()
}

fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_interpreter_basename(value: &str) -> bool {
    matches!(
        value,
        "python" | "python3" | "sh" | "bash" | "node" | "ruby" | "perl" | "java"
    )
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
        runtime_record_with_argv(
            session_id,
            seq_no,
            workload_id,
            exe_path,
            event_type,
            comm,
            &[],
        )
    }

    fn runtime_record_with_argv(
        session_id: &str,
        seq_no: u64,
        workload_id: Option<&str>,
        exe_path: &str,
        event_type: RuntimeEventType,
        comm: &str,
        argv: &[&str],
    ) -> EvidenceRecord {
        runtime_record_with_argv_quality(
            session_id,
            seq_no,
            workload_id,
            exe_path,
            event_type,
            comm,
            argv,
            !argv.is_empty(),
            false,
            false,
            false,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn runtime_record_with_argv_quality(
        session_id: &str,
        seq_no: u64,
        workload_id: Option<&str>,
        exe_path: &str,
        event_type: RuntimeEventType,
        comm: &str,
        argv: &[&str],
        argv_complete: bool,
        argv_truncated: bool,
        argv_read_error: bool,
        filename_truncated: bool,
        filename_read_error: bool,
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
                argv: argv.iter().map(|value| value.to_string()).collect(),
                argv_complete,
                argv_truncated,
                argv_read_error,
                filename_truncated,
                filename_read_error,
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

        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
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
    fn exec_attempt_is_counted_but_not_generated_as_acceptable_event_type() {
        let files = TestFiles::new("exec-attempt-event-type");
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
                    Some("workload-a"),
                    "/usr/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                ),
            ],
            2,
        );

        let output = train(&[&files], None);

        assert_eq!(output.metadata.observed_event_type_counts["exec"], 1);
        assert_eq!(
            output.metadata.observed_event_type_counts["exec-attempt"],
            1
        );
        assert_eq!(
            output.metadata.generated_acceptable_event_types,
            vec!["exec"]
        );
        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert_eq!(output.policy.acceptable.event_types, vec!["exec"]);
    }

    #[test]
    fn complete_exec_attempt_invocations_train_exact_argv_policy_and_count_duplicates() {
        let files = TestFiles::new("exec-attempt-metadata");
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
                runtime_record_with_argv(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/local/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["python", "-m", "uvicorn", "app:app"],
                ),
                runtime_record_with_argv(
                    SESSION_A,
                    3,
                    Some("workload-a"),
                    "/usr/local/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["python", "-m", "uvicorn", "app:app"],
                ),
            ],
            3,
        );

        let output = train(&[&files], None);

        assert_eq!(
            output.metadata.observed_exec_attempt_invocations,
            vec![ObservedInvocation {
                exe_path: String::from("/usr/local/bin/python"),
                argv: vec![
                    String::from("python"),
                    String::from("-m"),
                    String::from("uvicorn"),
                    String::from("app:app")
                ],
                count: 2,
                sessions_seen: 1,
                workload_id: Some(String::from("workload-a")),
            }]
        );
        assert_eq!(
            output.metadata.observed_interpreter_invocations,
            output.metadata.observed_exec_attempt_invocations
        );
        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert_eq!(output.policy.acceptable.event_types, vec!["exec"]);
        assert_eq!(
            output.policy.acceptable.argv_sensitive_exec_paths,
            vec![String::from("/usr/local/bin/python")]
        );
        assert_eq!(output.policy.acceptable.allowed_invocations.len(), 1);
        assert_eq!(
            output.policy.acceptable.allowed_invocations[0].exe_path,
            "/usr/local/bin/python"
        );
        assert_eq!(
            output.policy.acceptable.allowed_invocations[0].argv,
            vec![
                String::from("python"),
                String::from("-m"),
                String::from("uvicorn"),
                String::from("app:app")
            ]
        );
        assert_eq!(
            output.policy.acceptable.allowed_invocations[0].match_type,
            InvocationMatchType::Exact
        );
        assert_eq!(output.metadata.skipped_incomplete_argv_invocation_count, 0);
    }

    fn assert_incomplete_argv_invocation_is_skipped(
        name: &str,
        argv_complete: bool,
        argv_truncated: bool,
        argv_read_error: bool,
        filename_truncated: bool,
        filename_read_error: bool,
    ) {
        let files = TestFiles::new(name);
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
                runtime_record_with_argv_quality(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/local/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["python", "-m", "uvicorn", "app:app"],
                    argv_complete,
                    argv_truncated,
                    argv_read_error,
                    filename_truncated,
                    filename_read_error,
                ),
            ],
            2,
        );

        let output = train(&[&files], None);

        assert_eq!(output.policy.acceptable.exec_paths, vec!["/usr/bin/echo"]);
        assert!(
            output
                .policy
                .acceptable
                .argv_sensitive_exec_paths
                .is_empty()
        );
        assert!(output.policy.acceptable.allowed_invocations.is_empty());
        assert!(output.metadata.observed_exec_attempt_invocations.is_empty());
        assert!(output.metadata.observed_interpreter_invocations.is_empty());
        assert_eq!(output.metadata.skipped_incomplete_argv_invocation_count, 1);
    }

    #[test]
    fn argv_complete_false_exec_attempt_is_skipped_for_exact_argv_training() {
        assert_incomplete_argv_invocation_is_skipped(
            "argv-incomplete",
            false,
            false,
            false,
            false,
            false,
        );
    }

    #[test]
    fn argv_truncated_exec_attempt_is_skipped_for_exact_argv_training() {
        assert_incomplete_argv_invocation_is_skipped(
            "argv-truncated",
            true,
            true,
            false,
            false,
            false,
        );
    }

    #[test]
    fn argv_read_error_exec_attempt_is_skipped_for_exact_argv_training() {
        assert_incomplete_argv_invocation_is_skipped(
            "argv-read-error",
            true,
            false,
            true,
            false,
            false,
        );
    }

    #[test]
    fn filename_truncated_exec_attempt_is_skipped_for_exact_argv_training() {
        assert_incomplete_argv_invocation_is_skipped(
            "filename-truncated",
            true,
            false,
            false,
            true,
            false,
        );
    }

    #[test]
    fn filename_read_error_exec_attempt_is_skipped_for_exact_argv_training() {
        assert_incomplete_argv_invocation_is_skipped(
            "filename-read-error",
            true,
            false,
            false,
            false,
            true,
        );
    }

    #[test]
    fn exec_attempt_invocations_count_sessions_and_stay_deterministic() {
        let left = TestFiles::new("exec-attempt-session-left");
        left.write(
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
                runtime_record_with_argv(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "/usr/local/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["python", "-m", "app"],
                ),
            ],
            2,
        );
        let right = TestFiles::new("exec-attempt-session-right");
        right.write(
            SESSION_B,
            &[
                runtime_record_with_argv(
                    SESSION_B,
                    1,
                    Some("workload-a"),
                    "/bin/bash",
                    RuntimeEventType::ExecAttempt,
                    "bash",
                    &["bash", "-lc", "echo hi"],
                ),
                runtime_record_with_argv(
                    SESSION_B,
                    2,
                    Some("workload-a"),
                    "/usr/local/bin/python",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["python", "-m", "app"],
                ),
            ],
            2,
        );

        let output = train(&[&right, &left], None);

        assert_eq!(
            output.metadata.observed_exec_attempt_invocations,
            vec![
                ObservedInvocation {
                    exe_path: String::from("/bin/bash"),
                    argv: vec![
                        String::from("bash"),
                        String::from("-lc"),
                        String::from("echo hi")
                    ],
                    count: 1,
                    sessions_seen: 1,
                    workload_id: Some(String::from("workload-a")),
                },
                ObservedInvocation {
                    exe_path: String::from("/usr/local/bin/python"),
                    argv: vec![
                        String::from("python"),
                        String::from("-m"),
                        String::from("app")
                    ],
                    count: 2,
                    sessions_seen: 2,
                    workload_id: Some(String::from("workload-a")),
                },
            ]
        );
        assert_eq!(
            output.metadata.observed_interpreter_invocations,
            output.metadata.observed_exec_attempt_invocations
        );
    }

    #[test]
    fn interpreter_detection_uses_argv0_for_non_informative_exe_path() {
        let files = TestFiles::new("exec-attempt-argv0-interpreter");
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
                runtime_record_with_argv(
                    SESSION_A,
                    2,
                    Some("workload-a"),
                    "",
                    RuntimeEventType::ExecAttempt,
                    "python",
                    &["/usr/bin/python3", "script.py"],
                ),
                runtime_record_with_argv(
                    SESSION_A,
                    3,
                    Some("workload-a"),
                    "relative-launcher",
                    RuntimeEventType::ExecAttempt,
                    "node",
                    &["node", "server.js"],
                ),
                runtime_record_with_argv(
                    SESSION_A,
                    4,
                    Some("workload-a"),
                    "/usr/bin/custom-tool",
                    RuntimeEventType::ExecAttempt,
                    "custom-tool",
                    &["python", "ignored.py"],
                ),
            ],
            4,
        );

        let output = train(&[&files], None);

        assert_eq!(output.metadata.observed_exec_attempt_invocations.len(), 3);
        assert_eq!(
            output.metadata.observed_interpreter_invocations,
            vec![
                ObservedInvocation {
                    exe_path: String::new(),
                    argv: vec![String::from("/usr/bin/python3"), String::from("script.py")],
                    count: 1,
                    sessions_seen: 1,
                    workload_id: Some(String::from("workload-a")),
                },
                ObservedInvocation {
                    exe_path: String::from("relative-launcher"),
                    argv: vec![String::from("node"), String::from("server.js")],
                    count: 1,
                    sessions_seen: 1,
                    workload_id: Some(String::from("workload-a")),
                },
            ]
        );
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
        assert_eq!(output.policy.attestation.backend, "software-chain");
        assert_eq!(output.policy.attestation.mode, "");
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

        assert!(
            error
                .to_string()
                .contains("no non-empty successful exec paths")
        );
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
