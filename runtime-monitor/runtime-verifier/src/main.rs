use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use runtime_monitor_common::evidence::{RUNTIME_SUMMARY_SCHEMA_VERSION, RuntimeEvidenceState};
use runtime_monitor_common::{
    EventClassification, EvidenceEvent, EvidenceRecord, EvidenceSyntheticRecord, RuntimeEvent,
    RuntimePolicy, RuntimeSummary, SyntheticRecordType, classified_tpm_digest, classify_event,
    event_hash, final_summary_digest, hex_decode_32, hex_encode, policy_hash, replay_pcr_extend,
    session_start_digest, synthetic_record_hash,
};

const SUPPORTED_ATTESTATION_MODES: &[&str] =
    &["software-chain", "final-summary", "policy-triggered"];

#[derive(Debug)]
struct Args {
    policy: PathBuf,
    evidence: PathBuf,
    summary: PathBuf,
    report: Option<PathBuf>,
    require_tpm_quote: bool,
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
    tpm_summary_valid: bool,
    tpm_pcr_replay_valid: bool,
    tpm_quote_valid: bool,
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
            tpm_summary_valid: true,
            tpm_pcr_replay_valid: true,
            tpm_quote_valid: true,
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
            tpm_summary_valid: false,
            tpm_pcr_replay_valid: false,
            tpm_quote_valid: false,
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

#[derive(Debug, Clone)]
struct QuoteVerificationOptions {
    require_tpm_quote: bool,
    summary_dir: PathBuf,
}

impl QuoteVerificationOptions {
    #[cfg(test)]
    fn default_for_tests() -> Self {
        Self {
            require_tpm_quote: false,
            summary_dir: PathBuf::from("."),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TpmQuoteCheckRequest {
    ak_public_path: PathBuf,
    quote_message_path: PathBuf,
    quote_signature_path: PathBuf,
    quote_pcrs_path: PathBuf,
    nonce_hex: String,
    pcr_selection: String,
    hash_algorithm: String,
}

trait TpmQuoteCheckRunner {
    fn checkquote(&self, request: &TpmQuoteCheckRequest) -> Result<()>;
}

struct SystemTpmQuoteCheckRunner;

impl TpmQuoteCheckRunner for SystemTpmQuoteCheckRunner {
    fn checkquote(&self, request: &TpmQuoteCheckRequest) -> Result<()> {
        let args = vec![
            String::from("-u"),
            path_to_string(&request.ak_public_path, "AK public path")?,
            String::from("-m"),
            path_to_string(&request.quote_message_path, "quote message path")?,
            String::from("-s"),
            path_to_string(&request.quote_signature_path, "quote signature path")?,
            String::from("-f"),
            path_to_string(&request.quote_pcrs_path, "quote PCR path")?,
            String::from("-l"),
            request.pcr_selection.clone(),
            String::from("-q"),
            request.nonce_hex.clone(),
            String::from("-g"),
            request.hash_algorithm.clone(),
        ];
        let output = Command::new("tpm2_checkquote")
            .args(&args)
            .output()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    anyhow!("TPM tool `tpm2_checkquote` is not available")
                } else {
                    anyhow!("failed to run TPM tool `tpm2_checkquote`: {error}")
                }
            })?;
        validate_command_success("tpm2_checkquote", output)
    }
}

#[cfg(test)]
struct NoopTpmQuoteCheckRunner;

#[cfg(test)]
impl TpmQuoteCheckRunner for NoopTpmQuoteCheckRunner {
    fn checkquote(&self, _request: &TpmQuoteCheckRequest) -> Result<()> {
        Err(anyhow!(
            "unexpected TPM quote check in test without quote metadata"
        ))
    }
}

fn parse_args() -> Result<Args> {
    let mut policy = None;
    let mut evidence = None;
    let mut summary = None;
    let mut report = None;
    let mut require_tpm_quote = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => policy = args.next().map(PathBuf::from),
            "--evidence" => evidence = args.next().map(PathBuf::from),
            "--summary" => summary = args.next().map(PathBuf::from),
            "--report" => report = args.next().map(PathBuf::from),
            "--require-tpm-quote" => require_tpm_quote = true,
            _ => {
                return Err(anyhow!(
                    "unknown argument `{arg}`; usage: runtime-verifier --policy <runtime_policy.json> --evidence <runtime_events.jsonl> --summary <runtime_summary.json> [--report <verification_report.json>] [--require-tpm-quote]"
                ));
            }
        }
    }

    Ok(Args {
        policy: policy.ok_or_else(|| anyhow!("missing --policy <runtime_policy.json>"))?,
        evidence: evidence.ok_or_else(|| anyhow!("missing --evidence <runtime_events.jsonl>"))?,
        summary: summary.ok_or_else(|| anyhow!("missing --summary <runtime_summary.json>"))?,
        report,
        require_tpm_quote,
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

    let runner = SystemTpmQuoteCheckRunner;
    verify_replay_with_quote_runner(
        &policy,
        &summary,
        &records,
        &runner,
        QuoteVerificationOptions {
            require_tpm_quote: args.require_tpm_quote,
            summary_dir: summary_parent_dir(&args.summary),
        },
    )
}

#[cfg(test)]
fn verify_replay(
    policy: &RuntimePolicy,
    summary: &RuntimeSummary,
    records: &[EvidenceRecord],
) -> VerificationReport {
    let runner = NoopTpmQuoteCheckRunner;
    verify_replay_with_quote_runner(
        policy,
        summary,
        records,
        &runner,
        QuoteVerificationOptions::default_for_tests(),
    )
}

fn verify_replay_with_quote_runner<R>(
    policy: &RuntimePolicy,
    summary: &RuntimeSummary,
    records: &[EvidenceRecord],
    quote_runner: &R,
    quote_options: QuoteVerificationOptions,
) -> VerificationReport
where
    R: TpmQuoteCheckRunner,
{
    let mut checks = VerificationChecks::all_valid();
    let mut first_suspicious_event = None;
    let mut first_denied_event = None;
    let mut structural_reasons = Vec::new();
    let mut lifecycle = LifecycleState::default();
    let tpm_event_policy = tpm_event_policy(policy, &mut checks, &mut structural_reasons);
    let enforce_tpm_event_extends = summary.tpm.is_some();
    let mut tpm_event_replay = TpmEventReplayState::default();

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
                    &tpm_event_policy,
                    enforce_tpm_event_extends,
                    &mut tpm_event_replay,
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

    validate_tpm_summary(
        policy,
        summary,
        session_id,
        expected_policy_hash,
        &state,
        &tpm_event_replay,
        quote_runner,
        &quote_options,
        &mut checks,
        &mut structural_reasons,
    );

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

    let (decision, reason) = decision_for_valid_evidence(policy, summary, &counts, &mut checks);
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

#[derive(Default)]
struct TpmEventReplayState {
    digests: Vec<[u8; 32]>,
    next_extend_index: u64,
}

impl TpmEventReplayState {
    fn expected_next_index(&self) -> u64 {
        self.next_extend_index + 1
    }

    fn observe_extend(&mut self, digest: [u8; 32]) {
        self.next_extend_index += 1;
        self.digests.push(digest);
    }
}

struct TpmEventPolicy {
    backend_is_tpm: bool,
    mode: String,
    extend_on: Vec<EventClassification>,
}

impl TpmEventPolicy {
    fn is_policy_triggered_tpm(&self) -> bool {
        self.backend_is_tpm && self.mode == "policy-triggered"
    }

    fn requires_extend(&self, classification: EventClassification) -> bool {
        self.is_policy_triggered_tpm() && self.extend_on.contains(&classification)
    }
}

fn replay_runtime_event(
    event: &EvidenceEvent,
    policy: &RuntimePolicy,
    state: &mut RuntimeEvidenceState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
    first_suspicious_event: &mut Option<ReportEvent>,
    first_denied_event: &mut Option<ReportEvent>,
    tpm_event_policy: &TpmEventPolicy,
    enforce_tpm_event_extends: bool,
    tpm_event_replay: &mut TpmEventReplayState,
) {
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

    validate_event_tpm_metadata(
        event,
        &state.session_id,
        recomputed_event_hash,
        recomputed_classification.classification,
        &recomputed_classification.rule_id,
        tpm_event_policy,
        enforce_tpm_event_extends,
        tpm_event_replay,
        checks,
        structural_reasons,
    );

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

#[allow(clippy::too_many_arguments)]
fn validate_event_tpm_metadata(
    event: &EvidenceEvent,
    session_id: &[u8; 32],
    recomputed_event_hash: [u8; 32],
    recomputed_classification: EventClassification,
    recomputed_rule_id: &str,
    tpm_event_policy: &TpmEventPolicy,
    enforce_tpm_event_extends: bool,
    tpm_event_replay: &mut TpmEventReplayState,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    if event.tpm_extend_index.is_some() && !event.tpm_extended {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "tpm_extend_index is present but tpm_extended is false at seq_no {}",
            event.seq_no
        ));
    }

    if event.tpm_extended && !tpm_event_policy.is_policy_triggered_tpm() {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "per-event TPM metadata at seq_no {} requires attestation.backend `tpm` and mode `policy-triggered`; got backend_tpm={} mode={}",
            event.seq_no, tpm_event_policy.backend_is_tpm, tpm_event_policy.mode
        ));
        return;
    }

    let expected_extend = tpm_event_policy.requires_extend(recomputed_classification);
    if event.tpm_extended && !expected_extend {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "unexpected per-event TPM metadata at seq_no {} for classification {:?}",
            event.seq_no, recomputed_classification
        ));
        return;
    }

    if enforce_tpm_event_extends && expected_extend && !event.tpm_extended {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "missing required per-event TPM extend at seq_no {} for classification {:?}",
            event.seq_no, recomputed_classification
        ));
        return;
    }

    if !event.tpm_extended {
        return;
    }

    let Some(tpm_extend_index) = event.tpm_extend_index else {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "missing tpm_extend_index for extended event at seq_no {}",
            event.seq_no
        ));
        return;
    };

    let expected_index = tpm_event_replay.expected_next_index();
    if tpm_extend_index != expected_index {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "non-contiguous tpm_extend_index at seq_no {}: expected {} got {}",
            event.seq_no, expected_index, tpm_extend_index
        ));
        return;
    }

    let digest = classified_tpm_digest(
        session_id,
        event.seq_no,
        recomputed_event_hash,
        recomputed_classification,
        recomputed_rule_id,
    );
    tpm_event_replay.observe_extend(digest);
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

fn validate_tpm_summary<R>(
    policy: &RuntimePolicy,
    summary: &RuntimeSummary,
    session_id: [u8; 32],
    policy_hash_bytes: [u8; 32],
    state: &RuntimeEvidenceState,
    tpm_event_replay: &TpmEventReplayState,
    quote_runner: &R,
    quote_options: &QuoteVerificationOptions,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) where
    R: TpmQuoteCheckRunner,
{
    let policy_backend = normalized_attestation_backend(policy);
    let policy_uses_tpm = policy_backend == "tpm";

    let Some(tpm_summary) = summary.tpm.as_ref() else {
        validate_missing_tpm_quote(quote_options, checks, structural_reasons);
        if policy_uses_tpm
            && (policy.attestation.fail_on_tpm_error.unwrap_or(true)
                || !summary_indicates_tpm_failed_open(summary))
        {
            checks.tpm_summary_valid = false;
            structural_reasons.push(String::from(
                "TPM attestation policy requires summary.tpm metadata, but it is missing",
            ));
        }
        return;
    };

    if !policy_uses_tpm {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "summary.tpm is present but attestation.backend is `{}` rather than `tpm`",
            policy.attestation.backend
        ));
    }

    if !tpm_summary.enabled {
        checks.tpm_summary_valid = false;
        structural_reasons.push(String::from(
            "TPM summary metadata is present but not enabled",
        ));
    }

    let expected_hash_bank = expected_policy_hash_bank(policy);
    if tpm_summary.hash_bank != expected_hash_bank {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "TPM summary hash_bank mismatch: expected {} from policy got {}",
            expected_hash_bank, tpm_summary.hash_bank
        ));
    }

    if tpm_summary.hash_bank != "sha256" {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "unsupported TPM summary hash_bank `{}`; only sha256 is supported",
            tpm_summary.hash_bank
        ));
    }

    match policy.attestation.runtime_pcr {
        Some(expected_runtime_pcr) if tpm_summary.runtime_pcr == expected_runtime_pcr => {}
        Some(expected_runtime_pcr) => {
            checks.tpm_summary_valid = false;
            structural_reasons.push(format!(
                "TPM summary runtime_pcr mismatch: expected {} from policy got {}",
                expected_runtime_pcr, tpm_summary.runtime_pcr
            ));
        }
        None => {
            checks.tpm_summary_valid = false;
            structural_reasons.push(String::from(
                "summary.tpm is present but attestation.runtime_pcr is missing from policy",
            ));
        }
    }

    if tpm_summary.runtime_pcr > 23 {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "TPM summary runtime_pcr must be in range 0..=23, got {}",
            tpm_summary.runtime_pcr
        ));
    }

    let expected_event_extend_count = tpm_event_replay.digests.len() as u64;
    if tpm_summary.event_extend_count != expected_event_extend_count {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "TPM summary event_extend_count mismatch: expected {} got {}",
            expected_event_extend_count, tpm_summary.event_extend_count
        ));
    }

    let initial_pcr = decode_required_tpm_hex_32_field(
        tpm_summary.initial_pcr.as_deref(),
        "summary.tpm.initial_pcr",
        checks,
        structural_reasons,
    );
    let after_session_start_pcr = decode_required_tpm_hex_32_field(
        tpm_summary.after_session_start_pcr.as_deref(),
        "summary.tpm.after_session_start_pcr",
        checks,
        structural_reasons,
    );
    let final_pcr = decode_required_tpm_hex_32_field(
        tpm_summary.final_pcr.as_deref(),
        "summary.tpm.final_pcr",
        checks,
        structural_reasons,
    );
    let recorded_session_start_digest = decode_tpm_hex_32_field(
        &tpm_summary.session_start_digest,
        "summary.tpm.session_start_digest",
        checks,
        structural_reasons,
    );
    let recorded_final_summary_digest = decode_tpm_hex_32_field(
        &tpm_summary.final_summary_digest,
        "summary.tpm.final_summary_digest",
        checks,
        structural_reasons,
    );

    match &summary.final_summary_digest {
        Some(top_level_digest) if top_level_digest == &tpm_summary.final_summary_digest => {}
        Some(top_level_digest) => {
            checks.tpm_summary_valid = false;
            structural_reasons.push(format!(
                "summary final_summary_digest mismatch: top-level {} differs from TPM summary {}",
                top_level_digest, tpm_summary.final_summary_digest
            ));
        }
        None => {
            checks.tpm_summary_valid = false;
            structural_reasons.push(String::from(
                "summary.tpm is present but top-level final_summary_digest is missing",
            ));
        }
    }

    let expected_session_start_digest = session_start_digest(
        &session_id,
        policy_hash_bytes,
        &summary.workload_id,
        &summary.collection_mode,
    );
    let expected_final_summary_digest = final_summary_digest(
        &session_id,
        state.software_chain_head,
        state.event_count,
        state.synthetic_record_count,
        state.acceptable_count,
        state.suspicious_count,
        state.denied_count,
        summary.dropped_events,
        policy_hash_bytes,
    );

    if let Some(recorded) = recorded_session_start_digest
        && recorded != expected_session_start_digest
    {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "TPM session_start_digest mismatch: expected {} got {}",
            hex_encode(&expected_session_start_digest),
            tpm_summary.session_start_digest
        ));
    }

    if let Some(recorded) = recorded_final_summary_digest
        && recorded != expected_final_summary_digest
    {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!(
            "TPM final_summary_digest mismatch: expected {} got {}",
            hex_encode(&expected_final_summary_digest),
            tpm_summary.final_summary_digest
        ));
    }

    if let (
        Some(initial_pcr),
        Some(after_session_start_pcr),
        Some(final_pcr),
        Some(recorded_session_start_digest),
        Some(recorded_final_summary_digest),
    ) = (
        initial_pcr,
        after_session_start_pcr,
        final_pcr,
        recorded_session_start_digest,
        recorded_final_summary_digest,
    ) {
        let expected_after_session = replay_pcr_extend(initial_pcr, recorded_session_start_digest);
        if expected_after_session != after_session_start_pcr {
            checks.tpm_pcr_replay_valid = false;
            structural_reasons.push(format!(
                "TPM summary PCR replay mismatch after session-start: expected {} got {}",
                hex_encode(&expected_after_session),
                tpm_summary
                    .after_session_start_pcr
                    .as_deref()
                    .unwrap_or("<missing>")
            ));
        }

        let mut expected_pcr = expected_after_session;
        for digest in &tpm_event_replay.digests {
            expected_pcr = replay_pcr_extend(expected_pcr, *digest);
        }

        let expected_final_pcr = replay_pcr_extend(expected_pcr, recorded_final_summary_digest);
        if expected_final_pcr != final_pcr {
            checks.tpm_pcr_replay_valid = false;
            structural_reasons.push(format!(
                "TPM summary PCR replay mismatch after final-summary: expected {} got {}",
                hex_encode(&expected_final_pcr),
                tpm_summary.final_pcr.as_deref().unwrap_or("<missing>")
            ));
        }
    }

    validate_tpm_quote_summary(
        tpm_summary,
        quote_runner,
        quote_options,
        checks,
        structural_reasons,
    );
}

fn validate_missing_tpm_quote(
    quote_options: &QuoteVerificationOptions,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) {
    if quote_options.require_tpm_quote {
        checks.tpm_quote_valid = false;
        structural_reasons.push(String::from(
            "TPM quote is required but summary.tpm.quote metadata is missing",
        ));
    }
}

fn validate_tpm_quote_summary<R>(
    tpm_summary: &runtime_monitor_common::TpmSummary,
    quote_runner: &R,
    quote_options: &QuoteVerificationOptions,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) where
    R: TpmQuoteCheckRunner,
{
    let Some(quote) = tpm_summary.quote.as_ref() else {
        validate_missing_tpm_quote(quote_options, checks, structural_reasons);
        return;
    };

    let nonce_hex = match validate_quote_nonce(&quote.nonce_hex) {
        Ok(nonce_hex) => Some(nonce_hex),
        Err(error) => {
            checks.tpm_quote_valid = false;
            structural_reasons.push(format!("invalid summary.tpm.quote.nonce_hex: {error}"));
            None
        }
    };

    let expected_pcr_selection = format!("{}:{}", tpm_summary.hash_bank, tpm_summary.runtime_pcr);
    if quote.pcr_selection != expected_pcr_selection {
        checks.tpm_quote_valid = false;
        structural_reasons.push(format!(
            "TPM quote PCR selection mismatch: expected {} got {}",
            expected_pcr_selection, quote.pcr_selection
        ));
    }

    let quote_message_path = resolve_summary_relative_path(
        &quote.quote_message_path,
        "summary.tpm.quote.quote_message_path",
        quote_options,
        checks,
        structural_reasons,
    );
    let quote_signature_path = resolve_summary_relative_path(
        &quote.quote_signature_path,
        "summary.tpm.quote.quote_signature_path",
        quote_options,
        checks,
        structural_reasons,
    );
    let quote_pcrs_path = resolve_summary_relative_path(
        &quote.quote_pcrs_path,
        "summary.tpm.quote.quote_pcrs_path",
        quote_options,
        checks,
        structural_reasons,
    );
    let ak_public_path = match quote.ak_public_path.as_deref() {
        Some(path) => resolve_summary_relative_path(
            path,
            "summary.tpm.quote.ak_public_path",
            quote_options,
            checks,
            structural_reasons,
        ),
        None => {
            checks.tpm_quote_valid = false;
            structural_reasons.push(String::from(
                "summary.tpm.quote.ak_public_path is required when quote metadata is present",
            ));
            None
        }
    };

    let (
        Some(nonce_hex),
        Some(quote_message_path),
        Some(quote_signature_path),
        Some(quote_pcrs_path),
        Some(ak_public_path),
    ) = (
        nonce_hex,
        quote_message_path,
        quote_signature_path,
        quote_pcrs_path,
        ak_public_path,
    )
    else {
        return;
    };

    let request = TpmQuoteCheckRequest {
        ak_public_path,
        quote_message_path,
        quote_signature_path,
        quote_pcrs_path,
        nonce_hex,
        pcr_selection: quote.pcr_selection.clone(),
        hash_algorithm: tpm_summary.hash_bank.clone(),
    };

    // Stage 8 security boundary: tpm2_checkquote validates quote signature,
    // nonce, and PCR-file consistency against a configured AK public key. It
    // does not validate that the AK belongs to a certified hardware TPM or
    // trusted platform; AK/EK trust is deferred to a later Keylime/PKI stage.
    // tpm2_quote writes a serialized PCR blob by default. Stage 8 relies on
    // tpm2_checkquote to bind that PCR file to the quote, and on the existing
    // software PCR replay to validate final_pcr. Parsing the PCR blob directly
    // is intentionally left for a later hardening pass.
    if let Err(error) = quote_runner.checkquote(&request) {
        checks.tpm_quote_valid = false;
        structural_reasons.push(format!("TPM quote check failed: {error}"));
    }
}

fn normalized_attestation_backend(policy: &RuntimePolicy) -> String {
    policy.attestation.backend.trim().to_ascii_lowercase()
}

fn tpm_event_policy(
    policy: &RuntimePolicy,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) -> TpmEventPolicy {
    let backend = normalized_attestation_backend(policy);
    let backend_is_tpm = backend == "tpm";
    let mode = policy.attestation.mode.trim().to_ascii_lowercase();
    let mut extend_on = Vec::new();

    if backend != "none" && backend != "tpm" {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "unsupported attestation.backend `{}`; expected `none` or `tpm`",
            policy.attestation.backend
        ));
    }
    if !SUPPORTED_ATTESTATION_MODES.contains(&mode.as_str()) {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(format!(
            "unsupported attestation.mode `{}`; expected one of {}",
            policy.attestation.mode,
            SUPPORTED_ATTESTATION_MODES.join(", ")
        ));
    }

    for value in &policy.attestation.extend_on {
        let value = value.trim().to_ascii_lowercase();
        let classification = match value.as_str() {
            "acceptable" => EventClassification::Acceptable,
            "suspicious" => EventClassification::Suspicious,
            "denied" => EventClassification::Denied,
            _ => {
                checks.tpm_metadata_valid = false;
                structural_reasons
                    .push(format!("unsupported attestation.extend_on value `{value}`"));
                continue;
            }
        };

        if extend_on.contains(&classification) {
            checks.tpm_metadata_valid = false;
            structural_reasons.push(format!(
                "duplicate attestation.extend_on value `{value}` is not allowed"
            ));
            continue;
        }
        extend_on.push(classification);
    }

    if !extend_on.is_empty() && (!backend_is_tpm || mode != "policy-triggered") {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(String::from(
            "attestation.extend_on is only supported when backend is `tpm` and mode is `policy-triggered`",
        ));
    }

    if backend_is_tpm && mode == "policy-triggered" && extend_on.is_empty() {
        checks.tpm_metadata_valid = false;
        structural_reasons.push(String::from(
            "attestation.extend_on must not be empty when backend is `tpm` and mode is `policy-triggered`",
        ));
    }

    TpmEventPolicy {
        backend_is_tpm,
        mode,
        extend_on,
    }
}

fn expected_policy_hash_bank(policy: &RuntimePolicy) -> String {
    policy
        .attestation
        .hash_bank
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("sha256")
        .to_ascii_lowercase()
}

fn summary_indicates_tpm_failed_open(summary: &RuntimeSummary) -> bool {
    // Stage 7 compatibility: fail-open TPM sessions are identified by this
    // marker until the schema grows a structured TPM binding status field.
    summary
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("TPM binding failed open"))
}

fn summary_indicates_tpm_quote_failed_open(summary: &RuntimeSummary) -> bool {
    summary
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("TPM quote generation failed open"))
}

fn tpm_fail_open_software_evidence(policy: &RuntimePolicy, summary: &RuntimeSummary) -> bool {
    normalized_attestation_backend(policy) == "tpm"
        && !policy.attestation.fail_on_tpm_error.unwrap_or(true)
        && summary.tpm.is_none()
        && summary_indicates_tpm_failed_open(summary)
}

fn decode_required_tpm_hex_32_field(
    value: Option<&str>,
    label: &str,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) -> Option<[u8; 32]> {
    let Some(value) = value else {
        checks.tpm_summary_valid = false;
        structural_reasons.push(format!("{label} is required when summary.tpm is present"));
        return None;
    };

    decode_tpm_hex_32_field(value, label, checks, structural_reasons)
}

fn decode_tpm_hex_32_field(
    value: &str,
    label: &str,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) -> Option<[u8; 32]> {
    match hex_decode_32(value) {
        Ok(decoded) => Some(decoded),
        Err(error) => {
            checks.tpm_summary_valid = false;
            structural_reasons.push(format!("invalid {label}: {error}"));
            None
        }
    }
}

fn validate_quote_nonce(value: &str) -> Result<String> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| value.trim());
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!("expected a 64-character SHA-256 hex nonce"));
    }
    Ok(value.to_ascii_lowercase())
}

fn resolve_summary_relative_path(
    value: &str,
    label: &str,
    quote_options: &QuoteVerificationOptions,
    checks: &mut VerificationChecks,
    structural_reasons: &mut Vec<String>,
) -> Option<PathBuf> {
    match validate_summary_relative_path(value, label) {
        Ok(path) => Some(quote_options.summary_dir.join(path)),
        Err(error) => {
            checks.tpm_quote_valid = false;
            structural_reasons.push(error.to_string());
            None
        }
    }
}

fn validate_summary_relative_path(value: &str, label: &str) -> Result<PathBuf> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(anyhow!("{label} must be a relative path"));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::ParentDir => {
                return Err(anyhow!("{label} must not contain `..` components"));
            }
            _ => return Err(anyhow!("{label} contains unsupported path components")),
        }
    }
    Ok(path.to_path_buf())
}

fn path_to_string(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{label} is not valid UTF-8: {}", path.display()))
}

fn validate_command_success(program: &str, output: Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!(
        "TPM tool `{program}` failed with status {}: {}",
        output.status,
        stderr.trim()
    ))
}

fn summary_parent_dir(summary_path: &Path) -> PathBuf {
    summary_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
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
    summary: &RuntimeSummary,
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

    if tpm_fail_open_software_evidence(policy, summary) {
        return (
            VerificationDecision::AcceptWithWarnings,
            String::from("TPM binding failed open; software evidence replay passed"),
        );
    }

    if summary_indicates_tpm_quote_failed_open(summary) {
        return (
            VerificationDecision::AcceptWithWarnings,
            String::from("TPM quote generation failed open; TPM PCR replay passed"),
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
        AcceptablePolicy, AttestationPolicy, DeniedPolicy, SuspiciousPolicy, TpmQuoteSummary,
        TpmSummary,
    };
    use std::cell::RefCell;

    const SESSION_ID: [u8; 32] = [7u8; 32];

    #[derive(Debug)]
    struct MockQuoteCheckRunner {
        calls: RefCell<Vec<TpmQuoteCheckRequest>>,
        fail: bool,
    }

    impl MockQuoteCheckRunner {
        fn success() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail: false,
            }
        }

        fn failure() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail: true,
            }
        }

        fn calls(&self) -> Vec<TpmQuoteCheckRequest> {
            self.calls.borrow().clone()
        }
    }

    impl TpmQuoteCheckRunner for MockQuoteCheckRunner {
        fn checkquote(&self, request: &TpmQuoteCheckRequest) -> Result<()> {
            self.calls.borrow_mut().push(request.clone());
            if self.fail {
                return Err(anyhow!("mock checkquote failure"));
            }
            Ok(())
        }
    }

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

    fn tpm_policy(fail_on_tpm_error: Option<bool>) -> RuntimePolicy {
        let mut policy = base_policy();
        policy.attestation = AttestationPolicy {
            backend: String::from("tpm"),
            mode: String::from("final-summary"),
            runtime_pcr: Some(23),
            hash_bank: Some(String::from("sha256")),
            fail_on_tpm_error,
            ..AttestationPolicy::default()
        };
        policy
    }

    fn policy_triggered_tpm_policy(
        extend_on: Vec<&str>,
        fail_on_tpm_error: Option<bool>,
    ) -> RuntimePolicy {
        let mut policy = tpm_policy(fail_on_tpm_error);
        policy.attestation.mode = String::from("policy-triggered");
        policy.attestation.extend_on = extend_on.into_iter().map(String::from).collect();
        policy
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
            tpm: None,
        }
    }

    fn attach_valid_tpm_summary(policy: &RuntimePolicy, summary: &mut RuntimeSummary) {
        attach_tpm_summary_for_records(policy, summary, &[]);
    }

    fn attach_tpm_summary_for_records(
        policy: &RuntimePolicy,
        summary: &mut RuntimeSummary,
        records: &[EvidenceRecord],
    ) {
        let session_id = hex_decode_32(&summary.session_id).expect("session");
        let policy_hash_bytes = policy_hash(policy);
        let software_chain_head = hex_decode_32(&summary.software_chain_head).expect("chain");
        let initial_pcr = [0u8; 32];
        let session_digest = session_start_digest(
            &session_id,
            policy_hash_bytes,
            &summary.workload_id,
            &summary.collection_mode,
        );
        let after_session_start_pcr = replay_pcr_extend(initial_pcr, session_digest);
        let final_digest = final_summary_digest(
            &session_id,
            software_chain_head,
            summary.event_count,
            summary.synthetic_record_count,
            summary.acceptable_count,
            summary.suspicious_count,
            summary.denied_count,
            summary.dropped_events,
            policy_hash_bytes,
        );
        let mut expected_pcr = after_session_start_pcr;
        let mut event_extend_count = 0u64;
        for record in records {
            let EvidenceRecord::RuntimeEvent(event) = record else {
                continue;
            };
            if !event.tpm_extended {
                continue;
            }

            event_extend_count += 1;
            let event_hash = hex_decode_32(&event.event_hash).expect("event hash");
            let digest = classified_tpm_digest(
                &session_id,
                event.seq_no,
                event_hash,
                event.classification,
                &event.rule_id,
            );
            expected_pcr = replay_pcr_extend(expected_pcr, digest);
        }
        let final_pcr = replay_pcr_extend(expected_pcr, final_digest);

        summary.final_summary_digest = Some(hex_encode(&final_digest));
        summary.tpm = Some(TpmSummary {
            enabled: true,
            hash_bank: String::from("sha256"),
            runtime_pcr: 23,
            reset_pcr: true,
            event_extend_count,
            initial_pcr: Some(hex_encode(&initial_pcr)),
            after_session_start_pcr: Some(hex_encode(&after_session_start_pcr)),
            final_pcr: Some(hex_encode(&final_pcr)),
            session_start_digest: hex_encode(&session_digest),
            final_summary_digest: hex_encode(&final_digest),
            quote: None,
        });
    }

    fn attach_valid_tpm_quote(summary: &mut RuntimeSummary) {
        summary.tpm.as_mut().expect("tpm").quote = Some(TpmQuoteSummary {
            nonce_hex: String::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            pcr_selection: String::from("sha256:23"),
            quote_message_path: String::from("tpm_quote/session.quote.msg"),
            quote_signature_path: String::from("tpm_quote/session.quote.sig"),
            quote_pcrs_path: String::from("tpm_quote/session.quote.pcrs"),
            ak_public_path: Some(String::from("tpm_quote/session.akpub.pem")),
        });
    }

    fn mark_runtime_tpm_extended(records: &mut [EvidenceRecord], record_idx: usize, index: u64) {
        let EvidenceRecord::RuntimeEvent(event) = &mut records[record_idx] else {
            panic!("expected runtime event at index {record_idx}");
        };
        event.tpm_extended = true;
        event.tpm_extend_index = Some(index);
    }

    fn verify_fixture(
        policy: &RuntimePolicy,
        events: &[EvidenceRecord],
        summary: &RuntimeSummary,
    ) -> VerificationReport {
        verify_replay(policy, summary, events)
    }

    fn verify_fixture_with_quote_runner<R>(
        policy: &RuntimePolicy,
        events: &[EvidenceRecord],
        summary: &RuntimeSummary,
        runner: &R,
        require_tpm_quote: bool,
    ) -> VerificationReport
    where
        R: TpmQuoteCheckRunner,
    {
        verify_replay_with_quote_runner(
            policy,
            summary,
            events,
            runner,
            QuoteVerificationOptions {
                require_tpm_quote,
                summary_dir: PathBuf::from("/tmp/runtime-summary-dir"),
            },
        )
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
    fn valid_tpm_summary_pcr_replay_accepts() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert!(report.checks.tpm_summary_valid);
        assert!(report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn valid_tpm_quote_metadata_runs_checkquote_and_accepts() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        attach_valid_tpm_quote(&mut summary);
        let runner = MockQuoteCheckRunner::success();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, false);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert!(report.checks.tpm_quote_valid);
        assert_eq!(
            runner.calls(),
            vec![TpmQuoteCheckRequest {
                ak_public_path: PathBuf::from(
                    "/tmp/runtime-summary-dir/tpm_quote/session.akpub.pem"
                ),
                quote_message_path: PathBuf::from(
                    "/tmp/runtime-summary-dir/tpm_quote/session.quote.msg"
                ),
                quote_signature_path: PathBuf::from(
                    "/tmp/runtime-summary-dir/tpm_quote/session.quote.sig"
                ),
                quote_pcrs_path: PathBuf::from(
                    "/tmp/runtime-summary-dir/tpm_quote/session.quote.pcrs"
                ),
                nonce_hex: String::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                pcr_selection: String::from("sha256:23"),
                hash_algorithm: String::from("sha256"),
            }]
        );
    }

    #[test]
    fn tpm_quote_check_failure_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        attach_valid_tpm_quote(&mut summary);
        let runner = MockQuoteCheckRunner::failure();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, false);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_quote_valid);
        assert!(report.reason.contains("TPM quote check failed"));
    }

    #[test]
    fn required_tpm_quote_missing_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        let runner = MockQuoteCheckRunner::success();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, true);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_quote_valid);
        assert!(report.reason.contains("TPM quote is required"));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn tpm_summary_without_quote_still_accepts_when_quote_not_required() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert!(report.checks.tpm_quote_valid);
    }

    #[test]
    fn quote_metadata_rejects_absolute_or_parent_paths() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        attach_valid_tpm_quote(&mut summary);
        let quote = summary
            .tpm
            .as_mut()
            .expect("tpm")
            .quote
            .as_mut()
            .expect("quote");
        quote.quote_message_path = String::from("/tmp/quote.msg");
        quote.quote_signature_path = String::from("../quote.sig");
        let runner = MockQuoteCheckRunner::success();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, false);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_quote_valid);
        assert!(report.reason.contains("relative path"));
        assert!(report.reason.contains("must not contain `..`"));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn quote_metadata_rejects_invalid_nonce() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        attach_valid_tpm_quote(&mut summary);
        summary
            .tpm
            .as_mut()
            .expect("tpm")
            .quote
            .as_mut()
            .expect("quote")
            .nonce_hex = String::from("abcd");
        let runner = MockQuoteCheckRunner::success();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, false);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_quote_valid);
        assert!(report.reason.contains("nonce_hex"));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn quote_metadata_rejects_pcr_selection_mismatch() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        attach_valid_tpm_quote(&mut summary);
        summary
            .tpm
            .as_mut()
            .expect("tpm")
            .quote
            .as_mut()
            .expect("quote")
            .pcr_selection = String::from("sha256:22");
        let runner = MockQuoteCheckRunner::success();

        let report = verify_fixture_with_quote_runner(&policy, &events, &summary, &runner, false);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_quote_valid);
        assert!(report.reason.contains("PCR selection"));
    }

    #[test]
    fn unsupported_attestation_mode_is_invalid_evidence() {
        let mut policy = tpm_policy(Some(true));
        policy.attestation.mode = String::from("unknown-mode");
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("attestation.mode"));
    }

    #[test]
    fn final_summary_mode_with_empty_extend_on_accepts_valid_tpm_summary() {
        let mut policy = tpm_policy(Some(true));
        policy.attestation.extend_on.clear();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::Accept);
        assert!(report.checks.tpm_metadata_valid);
        assert!(report.checks.tpm_summary_valid);
        assert!(report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn policy_triggered_mode_with_empty_extend_on_is_invalid_evidence() {
        let mut policy = tpm_policy(Some(true));
        policy.attestation.mode = String::from("policy-triggered");
        policy.attestation.extend_on.clear();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("extend_on"));
    }

    #[test]
    fn non_empty_extend_on_in_final_summary_mode_is_invalid_evidence() {
        let mut policy = tpm_policy(Some(true));
        policy.attestation.extend_on = vec![String::from("suspicious")];
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("extend_on"));
    }

    #[test]
    fn wrong_tpm_session_start_digest_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").session_start_digest = hex_encode(&[0xabu8; 32]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
    }

    #[test]
    fn wrong_tpm_final_summary_digest_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        let wrong_digest = hex_encode(&[0xabu8; 32]);
        summary.final_summary_digest = Some(wrong_digest.clone());
        summary.tpm.as_mut().expect("tpm").final_summary_digest = wrong_digest;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
    }

    #[test]
    fn wrong_tpm_after_session_pcr_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").after_session_start_pcr =
            Some(hex_encode(&[0xabu8; 32]));

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn wrong_tpm_final_pcr_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").final_pcr = Some(hex_encode(&[0xabu8; 32]));

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn tpm_summary_missing_required_pcr_is_invalid_evidence() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").initial_pcr = None;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
    }

    #[test]
    fn tpm_summary_present_with_non_tpm_policy_is_invalid_evidence() {
        let policy = base_policy();
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
        assert!(report.reason.contains("attestation.backend"));
    }

    #[test]
    fn tpm_policy_requires_tpm_summary_by_default() {
        let policy = tpm_policy(None);
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
        assert!(report.reason.contains("summary.tpm"));
    }

    #[test]
    fn tpm_policy_allows_missing_tpm_summary_when_failure_failed_open() {
        let policy = tpm_policy(Some(false));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        summary.attestation_status = String::from("warning");
        summary.failure_reason = Some(String::from("TPM binding failed open: mock TPM failure"));

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::AcceptWithWarnings);
        assert!(report.checks.tpm_summary_valid);
        assert!(report.reason.contains("TPM binding failed open"));
    }

    #[test]
    fn tpm_policy_missing_tpm_summary_without_failed_open_reason_is_invalid_evidence() {
        let policy = tpm_policy(Some(false));
        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
    }

    #[test]
    fn tpm_summary_hash_bank_must_match_policy() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").hash_bank = String::from("sha384");

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
        assert!(report.reason.contains("hash_bank"));
    }

    #[test]
    fn tpm_summary_runtime_pcr_must_match_policy() {
        let policy = tpm_policy(Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        attach_valid_tpm_summary(&policy, &mut summary);
        summary.tpm.as_mut().expect("tpm").runtime_pcr = 22;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
        assert!(report.reason.contains("runtime_pcr"));
    }

    #[test]
    fn valid_policy_triggered_tpm_event_pcr_replay_accepts() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) = evidence_fixture(
            &policy,
            vec![runtime_event("/tmp/evil-a"), runtime_event("/tmp/evil-b")],
        );
        mark_runtime_tpm_extended(&mut events, 3, 1);
        mark_runtime_tpm_extended(&mut events, 4, 2);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::AcceptWithWarnings);
        assert!(report.checks.tpm_metadata_valid);
        assert!(report.checks.tpm_summary_valid);
        assert!(report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn missing_expected_event_tpm_extend_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(
            report
                .reason
                .contains("missing required per-event TPM extend")
        );
    }

    #[test]
    fn unexpected_event_tpm_extend_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) =
            evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        mark_runtime_tpm_extended(&mut events, 3, 1);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("unexpected per-event TPM metadata"));
    }

    #[test]
    fn final_summary_mode_rejects_runtime_tpm_metadata() {
        let policy = tpm_policy(Some(true));
        let (mut events, mut summary) =
            evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);
        mark_runtime_tpm_extended(&mut events, 3, 1);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("policy-triggered"));
    }

    #[test]
    fn missing_event_tpm_extend_index_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);
        mark_runtime_tpm_extended(&mut events, 3, 1);
        let EvidenceRecord::RuntimeEvent(event) = &mut events[3] else {
            panic!("expected runtime event");
        };
        event.tpm_extend_index = None;
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("missing tpm_extend_index"));
    }

    #[test]
    fn non_contiguous_event_tpm_extend_index_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);
        mark_runtime_tpm_extended(&mut events, 3, 2);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("non-contiguous tpm_extend_index"));
    }

    #[test]
    fn wrong_event_tpm_pcr_replay_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);
        mark_runtime_tpm_extended(&mut events, 3, 1);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);
        summary.tpm.as_mut().expect("tpm").final_pcr = Some(hex_encode(&[0xabu8; 32]));

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_pcr_replay_valid);
    }

    #[test]
    fn wrong_event_extend_count_is_invalid_evidence() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(true));
        let (mut events, mut summary) = evidence_fixture(&policy, vec![runtime_event("/tmp/evil")]);
        mark_runtime_tpm_extended(&mut events, 3, 1);
        attach_tpm_summary_for_records(&policy, &mut summary, &events);
        summary.tpm.as_mut().expect("tpm").event_extend_count = 99;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_summary_valid);
        assert!(report.reason.contains("event_extend_count"));
    }

    #[test]
    fn partial_event_tpm_fail_open_is_software_evidence_with_warning() {
        let policy = policy_triggered_tpm_policy(vec!["suspicious"], Some(false));
        let (mut events, mut summary) = evidence_fixture(
            &policy,
            vec![runtime_event("/tmp/evil-a"), runtime_event("/tmp/evil-b")],
        );
        mark_runtime_tpm_extended(&mut events, 3, 1);
        summary.attestation_status = String::from("warning");
        summary.failure_reason = Some(String::from(
            "TPM binding failed open: TPM event binding failed: mock TPM failure",
        ));
        summary.final_summary_digest = None;
        summary.tpm = None;

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::AcceptWithWarnings);
        assert!(report.checks.tpm_metadata_valid);
        assert!(report.checks.tpm_summary_valid);
        assert!(report.reason.contains("TPM binding failed open"));
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

    #[test]
    fn unsupported_attestation_backend_is_invalid_evidence() {
        let mut policy = base_policy();
        policy.attestation.backend = String::from("weird-backend");

        let (events, summary) = evidence_fixture(&policy, vec![runtime_event("/usr/bin/echo")]);

        let report = verify_fixture(&policy, &events, &summary);

        assert_eq!(report.decision, VerificationDecision::InvalidEvidence);
        assert!(!report.checks.tpm_metadata_valid);
        assert!(report.reason.contains("unsupported attestation.backend"));
    }
}
