use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use runtime_monitor_common::evidence::{RUNTIME_SUMMARY_SCHEMA_VERSION, RuntimeEvidenceState};
use runtime_monitor_common::{
    EventClassification, EvidenceEvent, EvidenceRecord, EvidenceSyntheticRecord, RuntimeEvent,
    RuntimePolicy, RuntimeSummary, SyntheticRecordType, classify_event, event_hash, hex_decode_32,
    hex_encode, policy_hash, synthetic_record_hash,
};

#[derive(Debug)]
struct Args {
    policy: PathBuf,
    evidence: PathBuf,
    summary: PathBuf,
    report: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum VerificationDecision {
    Accept,
    AcceptWithWarnings,
    Reject,
    InvalidEvidence,
}

impl VerificationDecision {
    fn as_display(self) -> &'static str {
        match self {
            Self::Accept => "ACCEPT",
            Self::AcceptWithWarnings => "ACCEPT-WITH-WARNINGS",
            Self::Reject => "REJECT",
            Self::InvalidEvidence => "INVALID-EVIDENCE",
        }
    }

    fn is_success(self) -> bool {
        matches!(self, Self::Accept | Self::AcceptWithWarnings)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct VerificationCounts {
    acceptable: u64,
    suspicious: u64,
    denied: u64,
    synthetic: u64,
    dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReportEvent {
    seq_no: u64,
    exe_path: String,
    rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VerificationChecks {
    schema_valid: bool,
    policy_hash_valid: bool,
    session_valid: bool,
    sequence_valid: bool,
    event_hashes_valid: bool,
    synthetic_hashes_valid: bool,
    classification_valid: bool,
    software_chain_valid: bool,
    counts_valid: bool,
    lifecycle_valid: bool,
    drop_policy_valid: bool,
    tpm_metadata_valid: bool,
}

impl VerificationChecks {
    fn all_valid() -> Self {
        Self {
            schema_valid: true,
            policy_hash_valid: true,
            session_valid: true,
            sequence_valid: true,
            event_hashes_valid: true,
            synthetic_hashes_valid: true,
            classification_valid: true,
            software_chain_valid: true,
            counts_valid: true,
            lifecycle_valid: true,
            drop_policy_valid: true,
            tpm_metadata_valid: true,
        }
    }

    fn all_invalid() -> Self {
        Self {
            schema_valid: false,
            policy_hash_valid: false,
            session_valid: false,
            sequence_valid: false,
            event_hashes_valid: false,
            synthetic_hashes_valid: false,
            classification_valid: false,
            software_chain_valid: false,
            counts_valid: false,
            lifecycle_valid: false,
            drop_policy_valid: false,
            tpm_metadata_valid: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VerificationReport {
    decision: VerificationDecision,
    reason: String,
    session_id: Option<String>,
    counts: VerificationCounts,
    first_suspicious_event: Option<ReportEvent>,
    first_denied_event: Option<ReportEvent>,
    checks: VerificationChecks,
}

impl VerificationReport {
    fn invalid_evidence(session_id: Option<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: VerificationDecision::InvalidEvidence,
            reason: reason.into(),
            session_id,
            counts: VerificationCounts::default(),
            first_suspicious_event: None,
            first_denied_event: None,
            checks: VerificationChecks::all_invalid(),
        }
    }
}

fn parse_args() -> Result<Args> {
    let mut policy = None;
    let mut evidence = None;
    let mut summary = None;
    let mut report = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => policy = args.next().map(PathBuf::from),
            "--evidence" => evidence = args.next().map(PathBuf::from),
            "--summary" => summary = args.next().map(PathBuf::from),
            "--report" => report = args.next().map(PathBuf::from),
            _ => {
                return Err(anyhow!(
                    "unknown argument `{arg}`; usage: runtime-verifier --policy <runtime_policy.json> --evidence <runtime_events.jsonl> --summary <runtime_summary.json> [--report <verification_report.json>]"
                ));
            }
        }
    }

    Ok(Args {
        policy: policy.ok_or_else(|| anyhow!("missing --policy <runtime_policy.json>"))?,
        evidence: evidence.ok_or_else(|| anyhow!("missing --evidence <runtime_events.jsonl>"))?,
        summary: summary.ok_or_else(|| anyhow!("missing --summary <runtime_summary.json>"))?,
        report,
    })
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

fn default_report_path(summary_path: &Path) -> PathBuf {
    summary_path.with_file_name("verification_report.json")
}

fn report_path(args: &Args) -> PathBuf {
    args.report
        .clone()
        .unwrap_or_else(|| default_report_path(&args.summary))
}

fn verify_from_paths(args: &Args) -> VerificationReport {
    let policy = match load_json::<RuntimePolicy>(&args.policy, "runtime policy") {
        Ok(policy) => policy,
        Err(error) => {
            return VerificationReport::invalid_evidence(
                None,
                format!("failed to parse verifier runtime policy: {error}"),
            );
        }
    };

    let summary = match load_json::<RuntimeSummary>(&args.summary, "runtime summary") {
        Ok(summary) => summary,
        Err(error) => {
            return VerificationReport::invalid_evidence(None, error.to_string());
        }
    };
    let session_id = Some(summary.session_id.clone());

    let records = match load_evidence_records(&args.evidence) {
        Ok(records) => records,
        Err(error) => {
            let mut report = VerificationReport::invalid_evidence(session_id, error.to_string());
            report.checks.session_valid = true;
            return report;
        }
    };

    verify_replay(&policy, &summary, &records)
}

fn verify_replay(
    policy: &RuntimePolicy,
    summary: &RuntimeSummary,
    records: &[EvidenceRecord],
) -> VerificationReport {
    let mut checks = VerificationChecks::all_valid();
    let mut first_suspicious_event = None;
    let mut first_denied_event = None;
    let mut structural_reasons = Vec::new();
    let mut lifecycle = LifecycleState::default();

    if summary.schema_version != RUNTIME_SUMMARY_SCHEMA_VERSION {
        checks.schema_valid = false;
        structural_reasons.push(format!(
            "unsupported runtime summary schema_version: expected {} got {}",
            RUNTIME_SUMMARY_SCHEMA_VERSION, summary.schema_version
        ));
    }

    let session_id = decode_hex_32_field(
        &summary.session_id,
        "summary.session_id",
        &mut structural_reasons,
    );
    if session_id.is_none() {
        checks.session_valid = false;
    }

    let expected_policy_hash = policy_hash(policy);
    match decode_hex_32_field(
        &summary.policy_hash,
        "summary.policy_hash",
        &mut structural_reasons,
    ) {
        Some(summary_policy_hash) if summary_policy_hash == expected_policy_hash => {}
        Some(_) => {
            checks.policy_hash_valid = false;
            structural_reasons.push(format!(
                "policy_hash mismatch: expected {} got {}",
                hex_encode(&expected_policy_hash),
                summary.policy_hash
            ));
        }
        None => checks.policy_hash_valid = false,
    }

    let summary_chain_head = match decode_hex_32_field(
        &summary.software_chain_head,
        "summary.software_chain_head",
        &mut structural_reasons,
    ) {
        Some(summary_chain_head) => Some(summary_chain_head),
        None => {
            checks.software_chain_valid = false;
            None
        }
    };

    let Some(session_id) = session_id else {
        return report_with_checks(
            VerificationDecision::InvalidEvidence,
            structural_reasons.join("; "),
            Some(summary.session_id.clone()),
            VerificationCounts {
                dropped: summary.dropped_events,
                ..VerificationCounts::default()
            },
            None,
            None,
            checks,
        );
    };

    let mut state = RuntimeEvidenceState::new(session_id);
    let mut expected_seq_no = 1u64;

    for (idx, record) in records.iter().enumerate() {
        let seq_no = record_seq_no(record);
        if lifecycle.seen_stop {
            checks.lifecycle_valid = false;
            structural_reasons.push(format!(
                "record found after monitor-stop at seq_no {seq_no}"
            ));
        }

        if record_session_id(record) != summary.session_id {
            checks.session_valid = false;
            structural_reasons.push(format!(
                "session mismatch at seq_no {}: expected {} got {}",
                seq_no,
                summary.session_id,
                record_session_id(record)
            ));
        }

        if seq_no != expected_seq_no {
            checks.sequence_valid = false;
            structural_reasons.push(format!(
                "non-contiguous seq_no: expected {} got {}",
                expected_seq_no, seq_no
            ));
        }
        expected_seq_no += 1;

        match record {
            EvidenceRecord::RuntimeEvent(event) => {
                if !lifecycle.seen_workload_target_bound {
                    checks.lifecycle_valid = false;
                    structural_reasons.push(format!(
                        "runtime event appeared before workload-target-bound at seq_no {}",
                        event.seq_no
                    ));
                }
                replay_runtime_event(
                    event,
                    policy,
                    &mut state,
                    &mut checks,
                    &mut structural_reasons,
                    &mut first_suspicious_event,
                    &mut first_denied_event,
                );
            }
            EvidenceRecord::Synthetic(record) => {
                validate_lifecycle_record(
                    record,
                    idx,
                    records.len(),
                    &mut lifecycle,
                    &mut checks,
                    &mut structural_reasons,
                );
                replay_synthetic_record(record, &mut state, &mut checks, &mut structural_reasons);
            }
        }
    }

    validate_lifecycle_completeness(&lifecycle, &mut checks, &mut structural_reasons);

    let counts = counts_from_state(&state, summary.dropped_events);

    if let Some(summary_chain_head) = summary_chain_head
        && summary_chain_head != state.software_chain_head
    {
        checks.software_chain_valid = false;
        structural_reasons.push(format!(
            "summary software_chain_head mismatch: expected {} got {}",
            hex_encode(&state.software_chain_head),
            summary.software_chain_head
        ));
    }

    if summary.event_count != state.event_count
        || summary.synthetic_record_count != state.synthetic_record_count
        || summary.acceptable_count != state.acceptable_count
        || summary.suspicious_count != state.suspicious_count
        || summary.denied_count != state.denied_count
    {
        checks.counts_valid = false;
        structural_reasons.push(format!(
            "summary counts mismatch: expected event/synthetic/acceptable/suspicious/denied {}/{}/{}/{}/{} got {}/{}/{}/{}/{}",
            state.event_count,
            state.synthetic_record_count,
            state.acceptable_count,
            state.suspicious_count,
            state.denied_count,
            summary.event_count,
            summary.synthetic_record_count,
            summary.acceptable_count,
            summary.suspicious_count,
            summary.denied_count
        ));
    }

    if !structural_reasons.is_empty() {
        return report_with_checks(
            VerificationDecision::InvalidEvidence,
            structural_reasons.join("; "),
            Some(summary.session_id.clone()),
            counts,
            first_suspicious_event,
            first_denied_event,
            checks,
        );
    }

    let (decision, reason) = decision_for_valid_evidence(policy, &counts, &mut checks);
    report_with_checks(
        decision,
        reason,
        Some(summary.session_id.clone()),
        counts,
        first_suspicious_event,
        first_denied_event,
        checks,
    )
}

#[derive(Default)]
struct LifecycleState {
    seen_monitor_start: bool,
    seen_policy_loaded: bool,
    seen_workload_target_bound: bool,
    seen_stop: bool,
}

fn replay_runtime_event(
    event: &EvidenceEvent,
    policy: &RuntimePolicy,
    state: &mut RuntimeEvidenceState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
    first_suspicious_event: &mut Option<ReportEvent>,
    first_denied_event: &mut Option<ReportEvent>,
) {
    if event.tpm_extended || event.tpm_extend_index.is_some() {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "TPM metadata is not supported in Stage 4 at seq_no {}: tpm_extended={} tpm_extend_index={:?}",
            event.seq_no, event.tpm_extended, event.tpm_extend_index
        ));
    }

    let recomputed_event_hash = event_hash(&state.session_id, event.seq_no, &event.event);
    match decode_hex_32_field(
        &event.event_hash,
        format!("EvidenceEvent.event_hash at seq_no {}", event.seq_no),
        structural_reasons,
    ) {
        Some(recorded_event_hash) if recorded_event_hash == recomputed_event_hash => {}
        Some(_) => {
            checks.event_hashes_valid = false;
            structural_reasons.push(format!(
                "event_hash mismatch at seq_no {}: expected {} got {}",
                event.seq_no,
                hex_encode(&recomputed_event_hash),
                event.event_hash
            ));
        }
        None => checks.event_hashes_valid = false,
    }

    let recomputed_classification = classify_event(&event.event, policy);
    if event.classification != recomputed_classification.classification {
        checks.classification_valid = false;
        structural_reasons.push(format!(
            "classification mismatch at seq_no {}: expected {:?} got {:?}",
            event.seq_no, recomputed_classification.classification, event.classification
        ));
    }

    if event.rule_id != recomputed_classification.rule_id {
        checks.classification_valid = false;
        structural_reasons.push(format!(
            "rule_id mismatch at seq_no {}: expected {} got {}",
            event.seq_no, recomputed_classification.rule_id, event.rule_id
        ));
    }

    let software_chain_head = state.update_chain(recomputed_event_hash);
    compare_chain_head(
        &event.software_chain_head,
        software_chain_head,
        format!(
            "EvidenceEvent.software_chain_head at seq_no {}",
            event.seq_no
        ),
        event.seq_no,
        checks,
        structural_reasons,
    );

    state.observe_classification(recomputed_classification.classification);
    match recomputed_classification.classification {
        EventClassification::Acceptable => {}
        EventClassification::Suspicious => {
            first_suspicious_event.get_or_insert_with(|| {
                report_event(
                    event.seq_no,
                    &event.event,
                    &recomputed_classification.rule_id,
                )
            });
        }
        EventClassification::Denied => {
            first_denied_event.get_or_insert_with(|| {
                report_event(
                    event.seq_no,
                    &event.event,
                    &recomputed_classification.rule_id,
                )
            });
        }
    }
}

fn replay_synthetic_record(
    record: &EvidenceSyntheticRecord,
    state: &mut RuntimeEvidenceState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    let recomputed_record_hash = synthetic_record_hash(
        &state.session_id,
        record.seq_no,
        record.record_type,
        &record.reason,
    );
    match decode_hex_32_field(
        &record.record_hash,
        format!(
            "EvidenceSyntheticRecord.record_hash at seq_no {}",
            record.seq_no
        ),
        structural_reasons,
    ) {
        Some(recorded_hash) if recorded_hash == recomputed_record_hash => {}
        Some(_) => {
            checks.synthetic_hashes_valid = false;
            structural_reasons.push(format!(
                "synthetic record_hash mismatch at seq_no {}: expected {} got {}",
                record.seq_no,
                hex_encode(&recomputed_record_hash),
                record.record_hash
            ));
        }
        None => checks.synthetic_hashes_valid = false,
    }

    let software_chain_head = state.update_chain(recomputed_record_hash);
    compare_chain_head(
        &record.software_chain_head,
        software_chain_head,
        format!(
            "EvidenceSyntheticRecord.software_chain_head at seq_no {}",
            record.seq_no
        ),
        record.seq_no,
        checks,
        structural_reasons,
    );
    state.observe_synthetic_record();
}

fn validate_lifecycle_record(
    record: &EvidenceSyntheticRecord,
    idx: usize,
    record_count: usize,
    lifecycle: &mut LifecycleState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    match record.record_type {
        SyntheticRecordType::MonitorStart => {
            if idx != 0 {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "monitor-start must be the first evidence record",
                );
            }
            if lifecycle.seen_monitor_start {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "duplicate monitor-start lifecycle record",
                );
            }
            lifecycle.seen_monitor_start = true;
        }
        SyntheticRecordType::PolicyLoaded => {
            if !lifecycle.seen_monitor_start
                || lifecycle.seen_policy_loaded
                || lifecycle.seen_workload_target_bound
                || lifecycle.seen_stop
            {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "policy-loaded lifecycle record is missing, duplicated, or out of order",
                );
            }
            lifecycle.seen_policy_loaded = true;
        }
        SyntheticRecordType::WorkloadTargetBound => {
            if !lifecycle.seen_monitor_start
                || !lifecycle.seen_policy_loaded
                || lifecycle.seen_workload_target_bound
                || lifecycle.seen_stop
            {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "workload-target-bound lifecycle record is missing, duplicated, or out of order",
                );
            }
            lifecycle.seen_workload_target_bound = true;
        }
        SyntheticRecordType::MonitorStop => {
            if !lifecycle.seen_monitor_start
                || !lifecycle.seen_policy_loaded
                || !lifecycle.seen_workload_target_bound
                || lifecycle.seen_stop
            {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "monitor-stop lifecycle record is missing, duplicated, or out of order",
                );
            }
            if idx + 1 != record_count {
                mark_lifecycle_invalid(
                    checks,
                    structural_reasons,
                    "monitor-stop must be the final evidence record",
                );
            }
            lifecycle.seen_stop = true;
        }
    }
}

fn validate_lifecycle_completeness(
    lifecycle: &LifecycleState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    if !lifecycle.seen_monitor_start {
        mark_lifecycle_invalid(
            checks,
            structural_reasons,
            "missing monitor-start lifecycle record",
        );
    }
    if !lifecycle.seen_policy_loaded {
        mark_lifecycle_invalid(
            checks,
            structural_reasons,
            "missing policy-loaded lifecycle record",
        );
    }
    if !lifecycle.seen_workload_target_bound {
        mark_lifecycle_invalid(
            checks,
            structural_reasons,
            "missing workload-target-bound lifecycle record",
        );
    }
    if !lifecycle.seen_stop {
        mark_lifecycle_invalid(
            checks,
            structural_reasons,
            "missing monitor-stop lifecycle record",
        );
    }
}

fn mark_lifecycle_invalid(
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
    reason: impl Into<String>,
) {
    checks.lifecycle_valid = false;
    structural_reasons.push(reason.into());
}

fn compare_chain_head(
    recorded: &str,
    expected: [u8; 32],
    label: impl AsRef<str>,
    seq_no: u64,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    match decode_hex_32_field(recorded, label, structural_reasons) {
        Some(recorded_chain_head) if recorded_chain_head == expected => {}
        Some(_) => {
            checks.software_chain_valid = false;
            structural_reasons.push(format!(
                "software_chain_head mismatch at seq_no {}: expected {} got {}",
                seq_no,
                hex_encode(&expected),
                recorded
            ));
        }
        None => checks.software_chain_valid = false,
    }
}

fn record_session_id(record: &EvidenceRecord) -> &str {
    match record {
        EvidenceRecord::RuntimeEvent(event) => &event.session_id,
        EvidenceRecord::Synthetic(record) => &record.session_id,
    }
}

fn record_seq_no(record: &EvidenceRecord) -> u64 {
    match record {
        EvidenceRecord::RuntimeEvent(event) => event.seq_no,
        EvidenceRecord::Synthetic(record) => record.seq_no,
    }
}

fn decode_hex_32_field(
    value: &str,
    label: impl AsRef<str>,
    structural_reasons: &mut Vec<String>,
) -> Option<[u8; 32]> {
    match hex_decode_32(value) {
        Ok(decoded) => Some(decoded),
        Err(error) => {
            structural_reasons.push(format!("invalid {}: {error}", label.as_ref()));
            None
        }
    }
}

fn decision_for_valid_evidence(
    policy: &RuntimePolicy,
    counts: &VerificationCounts,
    checks: &mut VerificationChecks,
) -> (VerificationDecision, String) {
    if counts.dropped > 0 && policy.attestation.fail_on_drops {
        checks.drop_policy_valid = false;
        return (
            VerificationDecision::Reject,
            format!("{} dropped events observed", counts.dropped),
        );
    }

    if counts.denied > 0 && policy.attestation.fail_on_denied {
        return (
            VerificationDecision::Reject,
            String::from("denied runtime behaviour observed"),
        );
    }

    if counts.suspicious > 0 && policy.attestation.fail_on_suspicious {
        return (
            VerificationDecision::Reject,
            String::from("suspicious runtime behaviour observed"),
        );
    }

    if counts.suspicious > 0 || counts.denied > 0 {
        return (
            VerificationDecision::AcceptWithWarnings,
            String::from("runtime behaviour produced warnings but policy does not reject it"),
        );
    }

    (
        VerificationDecision::Accept,
        String::from("all replay checks passed"),
    )
}

fn report_with_checks(
    decision: VerificationDecision,
    reason: impl Into<String>,
    session_id: Option<String>,
    counts: VerificationCounts,
    first_suspicious_event: Option<ReportEvent>,
    first_denied_event: Option<ReportEvent>,
    checks: VerificationChecks,
) -> VerificationReport {
    VerificationReport {
        decision,
        reason: reason.into(),
        session_id,
        counts,
        first_suspicious_event,
        first_denied_event,
        checks,
    }
}

fn report_event(seq_no: u64, event: &RuntimeEvent, rule_id: &str) -> ReportEvent {
    ReportEvent {
        seq_no,
        exe_path: event.exe_path.clone(),
        rule_id: rule_id.to_owned(),
    }
}

fn counts_from_state(state: &RuntimeEvidenceState, dropped: u64) -> VerificationCounts {
    VerificationCounts {
        acceptable: state.acceptable_count,
        suspicious: state.suspicious_count,
        denied: state.denied_count,
        synthetic: state.synthetic_record_count,
        dropped,
    }
}

fn write_report(report: &VerificationReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "failed to create verification report directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let file = File::create(path).map_err(|e| {
        anyhow!(
            "failed to create verification report {}: {e}",
            path.display()
        )
    })?;
    serde_json::to_writer_pretty(BufWriter::new(file), report).map_err(|e| {
        anyhow!(
            "failed to write verification report {}: {e}",
            path.display()
        )
    })
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let report = verify_from_paths(&args);
    let report_path = report_path(&args);
    write_report(&report, &report_path)?;

    println!(
        "{}: {}; report={}",
        report.decision.as_display(),
        report.reason,
        report_path.display()
    );

    if report.decision.is_success() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_monitor_common::evidence::RuntimeEventType;
    use runtime_monitor_common::{
        AcceptablePolicy, AttestationPolicy, DeniedPolicy, SuspiciousPolicy,
    };

    const SESSION_ID: [u8; 32] = [7u8; 32];

    fn push_synthetic(
        records: &mut Vec<EvidenceRecord>,
        state: &mut RuntimeEvidenceState,
        record_type: SyntheticRecordType,
        reason: &str,
    ) {
        let seq_no = state.advance_sequence();
        let record_hash = synthetic_record_hash(&state.session_id, seq_no, record_type, reason);
        let software_chain_head = state.update_chain(record_hash);
        state.observe_synthetic_record();

        records.push(EvidenceRecord::Synthetic(EvidenceSyntheticRecord {
            session_id: hex_encode(&SESSION_ID),
            seq_no,
            record_type,
            reason: reason.to_owned(),
            record_hash: hex_encode(&record_hash),
            software_chain_head: hex_encode(&software_chain_head),
        }));
    }

    fn push_runtime(
        records: &mut Vec<EvidenceRecord>,
        state: &mut RuntimeEvidenceState,
        policy: &RuntimePolicy,
        runtime_event: RuntimeEvent,
    ) {
        let seq_no = state.advance_sequence();
        let classification = classify_event(&runtime_event, policy);
        let event_hash_bytes = event_hash(&state.session_id, seq_no, &runtime_event);
        let software_chain_head = state.update_chain(event_hash_bytes);
        state.observe_classification(classification.classification);

        records.push(EvidenceRecord::RuntimeEvent(EvidenceEvent {
            session_id: hex_encode(&SESSION_ID),
            seq_no,
            event: runtime_event,
            classification: classification.classification,
            rule_id: classification.rule_id,
            reason: classification.reason,
            event_hash: hex_encode(&event_hash_bytes),
            software_chain_head: hex_encode(&software_chain_head),
            tpm_extended: false,
            tpm_extend_index: None,
        }));
    }

    fn base_policy() -> RuntimePolicy {
        RuntimePolicy {
            workload_id: String::from("workload-a"),
            profile_mode: String::from("minimal-behaviour"),
            acceptable: AcceptablePolicy {
                exec_paths: vec![String::from("/usr/bin/echo")],
                event_types: vec![String::from("exec"), String::from("fork")],
            },
            suspicious: SuspiciousPolicy {
                unknown_exec_path: true,
            },
            denied: DeniedPolicy {
                exec_paths: vec![String::from("/usr/bin/id")],
                comm_names: vec![String::from("evil")],
            },
            attestation: AttestationPolicy::default(),
        }
    }

    fn runtime_event(exe_path: &str) -> RuntimeEvent {
        RuntimeEvent {
            workload_index: 0,
            workload_id: Some(String::from("workload-a")),
            event_type: RuntimeEventType::Exec,
            timestamp_ns: 42,
            cgroup_id: 99,
            pid: 123,
            tgid: 123,
            ppid: 1,
            cpu: 2,
            comm: String::from("echo"),
            exe_path: exe_path.to_owned(),
        }
    }

    fn evidence_fixture(
        policy: &RuntimePolicy,
        runtime_events: Vec<RuntimeEvent>,
    ) -> (Vec<EvidenceRecord>, RuntimeSummary) {
        let mut state = RuntimeEvidenceState::new(SESSION_ID);
        let mut events = Vec::new();

        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::PolicyLoaded,
            "runtime policy loaded from configured policy",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::WorkloadTargetBound,
            "workload targets bound: collection_mode=scoped workloads=workload-a",
        );
        for runtime_event in runtime_events {
            push_runtime(&mut events, &mut state, policy, runtime_event);
        }
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStop,
            "monitor session stopped",
        );

        let summary = summary_for(policy, &state);

        (events, summary)
    }

    fn summary_for(policy: &RuntimePolicy, state: &RuntimeEvidenceState) -> RuntimeSummary {
        RuntimeSummary {
            schema_version: RUNTIME_SUMMARY_SCHEMA_VERSION,
            session_id: hex_encode(&SESSION_ID),
            workload_id: String::from("workload-a"),
            collection_mode: String::from("scoped"),
            policy_hash: hex_encode(&policy_hash(policy)),
            monitor_config_hash: None,
            attestation_status: String::from("passed"),
            failure_reason: None,
            event_count: state.event_count,
            synthetic_record_count: state.synthetic_record_count,
            acceptable_count: state.acceptable_count,
            suspicious_count: state.suspicious_count,
            denied_count: state.denied_count,
            dropped_events: 0,
            software_chain_head: hex_encode(&state.software_chain_head),
            final_summary_digest: None,
        }
    }

    fn verify_fixture(
        policy: &RuntimePolicy,
        events: &[EvidenceRecord],
        summary: &RuntimeSummary,
    ) -> VerificationReport {
        verify_replay(policy, summary, events)
    }

    #[test]
    fn valid_acceptable_evidence_accepts() {
        let policy = base_policy();
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert_eq!(report.counts.acceptable, 1);
        assert_eq!(report.counts.synthetic, 4);
    }

    #[test]
    fn suspicious_without_fail_policy_accepts_with_warnings() {
        let policy = base_policy();
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::AcceptWithWarnings);
        assert_eq!(report.counts.suspicious, 1);
        assert_eq!(
            report
                .first_suspicious_event
                .as_ref()
                .map(|event| event.seq_no),
            Some(4)
        );
    }

    #[test]
    fn suspicious_with_fail_policy_rejects() {
        let mut policy = base_policy();
        policy.attestation.fail_on_suspicious = true;
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Reject);
    }

    #[test]
    fn denied_with_fail_policy_rejects() {
        let policy = base_policy();
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/id")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Reject);
        assert_eq!(report.counts.denied, 1);
    }

    #[test]
    fn modified_event_hash_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        let EvidenceRecord::RuntimeEvent(event) = &mut events[3] else {
            panic!("expected runtime event");
        };
        event.event_hash = String::from("deadbeef");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.event_hashes_valid);
    }

    #[test]
    fn reason_mismatch_does_not_invalidate_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        let EvidenceRecord::RuntimeEvent(event) = &mut events[3] else {
            panic!("expected runtime event");
        };
        event.reason = String::from("different wording from monitor");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert!(report.checks.classification_valid);
    }

    #[test]
    fn non_contiguous_seq_no_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(
            &policy,
            vec![
                runtime_event("/usr/bin/echo"),
                runtime_event("/usr/bin/echo"),
            ],
        );
        let EvidenceRecord::RuntimeEvent(event) = &mut events[3] else {
            panic!("expected runtime event");
        };
        event.seq_no = 99;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.sequence_valid);
    }

    #[test]
    fn wrong_summary_software_chain_head_is_invalid_evidence() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.software_chain_head = String::from("deadbeef");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.software_chain_valid);
    }

    #[test]
    fn wrong_summary_policy_hash_is_invalid_evidence() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.policy_hash = String::from("deadbeef");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.policy_hash_valid);
    }

    #[test]
    fn mismatched_summary_counts_are_invalid_evidence() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.acceptable_count = 2;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.counts_valid);
    }

    #[test]
    fn missing_monitor_start_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        events.remove(0);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.lifecycle_valid);
    }

    #[test]
    fn missing_monitor_stop_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        events.pop();

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.lifecycle_valid);
    }

    #[test]
    fn lifecycle_records_out_of_order_are_invalid_evidence() {
        let policy = base_policy();
        let mut state = RuntimeEvidenceState::new(SESSION_ID);
        let mut events = Vec::new();
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::PolicyLoaded,
            "runtime policy loaded from configured policy",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::WorkloadTargetBound,
            "workload targets bound: collection_mode=scoped workloads=workload-a",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStop,
            "monitor session stopped",
        );
        let summary = summary_for(&policy, &state);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.lifecycle_valid);
        assert!(report.checks.sequence_valid);
        assert!(report.checks.synthetic_hashes_valid);
    }

    #[test]
    fn runtime_event_before_workload_target_bound_is_invalid_evidence() {
        let policy = base_policy();
        let mut state = RuntimeEvidenceState::new(SESSION_ID);
        let mut events = Vec::new();
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStart,
            "monitor session started",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::PolicyLoaded,
            "runtime policy loaded from configured policy",
        );
        push_runtime(
            &mut events,
            &mut state,
            &policy,
            runtime_event("/usr/bin/echo"),
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::WorkloadTargetBound,
            "workload targets bound: collection_mode=scoped workloads=workload-a",
        );
        push_synthetic(
            &mut events,
            &mut state,
            SyntheticRecordType::MonitorStop,
            "monitor session stopped",
        );
        let summary = summary_for(&policy, &state);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.lifecycle_valid);
        assert!(report.checks.sequence_valid);
        assert!(report.checks.event_hashes_valid);
        assert!(report.checks.synthetic_hashes_valid);
    }

    #[test]
    fn monitor_stop_not_final_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        events.swap(3, 4);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.lifecycle_valid);
    }

    #[test]
    fn modified_synthetic_record_hash_is_invalid_evidence() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        let EvidenceRecord::Synthetic(record) = &mut events[0] else {
            panic!("expected synthetic record");
        };
        record.record_hash = String::from("deadbeef");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.synthetic_hashes_valid);
    }

    #[test]
    fn wrong_synthetic_record_count_is_invalid_evidence() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.synthetic_record_count = 99;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.counts_valid);
    }

    #[test]
    fn dropped_events_with_fail_policy_reject() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.dropped_events = 1;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Reject);
        assert!(!report.checks.drop_policy_valid);
        assert_eq!(report.counts.dropped, 1);
    }

    #[test]
    fn unsupported_summary_schema_marks_schema_invalid_only() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.schema_version = RUNTIME_SUMMARY_SCHEMA_VERSION + 1;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.schema_valid);
        assert!(report.checks.session_valid);
    }

    #[test]
    fn tpm_metadata_is_invalid_until_tpm_stage() {
        let policy = base_policy();
        let (mut events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        let EvidenceRecord::RuntimeEvent(event) = &mut events[3] else {
            panic!("expected runtime event");
        };
        event.tpm_extended = true;
        event.tpm_extend_index = Some(1);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
    }
}
