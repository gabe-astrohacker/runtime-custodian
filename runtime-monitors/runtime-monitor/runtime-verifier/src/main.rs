use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum DefaultAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifierPolicy {
    workload_id: String,
    allowed_exec_paths: Vec<String>,
    forbidden_exec_paths: Vec<String>,
    default_action: DefaultAction,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EvidenceEvent {
    seq: u64,
    lost: u64,
    workload_id: Option<String>,
    workload_index: u32,
    event_type: String,
    pid: u32,
    tgid: u32,
    cgroup_id: u64,
    comm: String,
    exe_path: String,
    filename_read_ok: Option<bool>,
    filename_truncated: Option<bool>,
    filename_read_error: Option<i32>,
    ts_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EvidenceSummary {
    workload_id: Option<String>,
    collection_mode: String,
    event_count: usize,
    evidence_digest: String,
    final_seq: u64,
    final_lost: u64,
    #[serde(default)]
    malformed_samples: usize,
}

struct Args {
    policy: PathBuf,
    evidence: PathBuf,
    summary: Option<PathBuf>,
    allow_host_wide: bool,
    allow_missing_summary: bool,
    allow_empty_evidence: bool,
}

enum Verdict {
    Accept,
    Reject(String),
}

enum VerificationEvent<'a> {
    Exec(&'a EvidenceEvent),
    Fork,
    Unsupported(&'a EvidenceEvent),
}

impl<'a> VerificationEvent<'a> {
    fn from_event(event: &'a EvidenceEvent) -> Self {
        match event.event_type.as_str() {
            "exec" => Self::Exec(event),
            "fork" => Self::Fork,
            _ => Self::Unsupported(event),
        }
    }
}

struct RollingDigest {
    value: [u8; 32],
}

impl RollingDigest {
    fn new() -> Self {
        Self { value: [0; 32] }
    }

    fn update(&mut self, raw_event_line: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.value);
        hasher.update(raw_event_line);
        self.value.copy_from_slice(&hasher.finalize());
    }

    fn hex(&self) -> String {
        hex_bytes(&self.value)
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn reject_reason(reason: impl AsRef<str>, line_no: usize, event: &EvidenceEvent) -> String {
    let workload_id = event.workload_id.as_deref().unwrap_or("<unknown>");
    format!(
        "{}, line={}, workload_id={}, seq={}",
        reason.as_ref(),
        line_no,
        workload_id,
        event.seq
    )
}

fn reject_unknown_reason(reason: impl AsRef<str>, line_no: usize) -> String {
    format!(
        "{}, line={}, workload_id=<unknown>, seq=<unknown>",
        reason.as_ref(),
        line_no
    )
}

fn verify_event(
    policy: &VerifierPolicy,
    allowed: &HashSet<&str>,
    forbidden: &HashSet<&str>,
    event: VerificationEvent<'_>,
    line_no: usize,
) -> Option<String> {
    match event {
        VerificationEvent::Exec(event) => {
            verify_exec_event(policy, allowed, forbidden, event, line_no)
        }
        VerificationEvent::Fork => None,
        VerificationEvent::Unsupported(event) => Some(reject_reason(
            format!("unsupported event_type {}", event.event_type),
            line_no,
            event,
        )),
    }
}

fn verify_exec_event(
    policy: &VerifierPolicy,
    allowed: &HashSet<&str>,
    forbidden: &HashSet<&str>,
    event: &EvidenceEvent,
    line_no: usize,
) -> Option<String> {
    if event.filename_read_ok != Some(true) {
        let detail = event
            .filename_read_error
            .map(|error| format!(" error {error}"))
            .unwrap_or_default();
        return Some(reject_reason(
            format!("filename read failed or missing filename_read_ok{detail}"),
            line_no,
            event,
        ));
    }

    if event.filename_truncated != Some(false) {
        return Some(reject_reason(
            "filename truncated or missing filename_truncated",
            line_no,
            event,
        ));
    }

    if forbidden.contains(event.exe_path.as_str()) {
        return Some(reject_reason(
            format!("forbidden executable {}", event.exe_path),
            line_no,
            event,
        ));
    }

    if policy.default_action == DefaultAction::Deny && !allowed.contains(event.exe_path.as_str()) {
        return Some(reject_reason(
            format!(
                "executable {} not allowed by default deny policy",
                event.exe_path
            ),
            line_no,
            event,
        ));
    }

    None
}

#[derive(Debug, Clone)]
struct EvidenceRecord {
    line_no: usize,
    raw_line: Vec<u8>,
    event: Option<EvidenceEvent>,
    parse_error: Option<String>,
}

impl EvidenceRecord {
    fn parsed(line_no: usize, raw_line: Vec<u8>, event: EvidenceEvent) -> Self {
        Self {
            line_no,
            raw_line,
            event: Some(event),
            parse_error: None,
        }
    }

    fn parse_error(line_no: usize, raw_line: Vec<u8>, error: String) -> Self {
        Self {
            line_no,
            raw_line,
            event: None,
            parse_error: Some(error),
        }
    }
}

fn parse_args() -> Result<Args> {
    let mut policy = None;
    let mut evidence = None;
    let mut summary = None;
    let mut allow_host_wide = false;
    let mut allow_missing_summary = false;
    let mut allow_empty_evidence = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => policy = args.next().map(PathBuf::from),
            "--evidence" => evidence = args.next().map(PathBuf::from),
            "--summary" => summary = args.next().map(PathBuf::from),
            "--allow-host-wide" => allow_host_wide = true,
            "--allow-missing-summary" => allow_missing_summary = true,
            "--allow-empty-evidence" => allow_empty_evidence = true,
            _ => {
                return Err(anyhow!(
                    "unknown argument `{arg}`; usage: runtime-verifier --policy <policy.json> --evidence <events.jsonl> --summary <runtime_events.summary.json> [--allow-host-wide] [--allow-missing-summary] [--allow-empty-evidence]"
                ));
            }
        }
    }

    Ok(Args {
        policy: policy.ok_or_else(|| anyhow!("missing --policy <policy.json>"))?,
        evidence: evidence.ok_or_else(|| anyhow!("missing --evidence <events.jsonl>"))?,
        summary,
        allow_host_wide,
        allow_missing_summary,
        allow_empty_evidence,
    })
}

fn load_policy(path: &Path) -> Result<VerifierPolicy> {
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse policy {}: {e}", path.display()))
}

fn load_summary(path: &Path) -> Result<EvidenceSummary> {
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse summary {}: {e}", path.display()))
}

fn verify_evidence_with_options(
    policy: &VerifierPolicy,
    evidence_records: &[EvidenceRecord],
    summary: Option<&EvidenceSummary>,
    allow_host_wide: bool,
    allow_empty_evidence: bool,
) -> Result<Verdict> {
    let allowed: HashSet<&str> = policy
        .allowed_exec_paths
        .iter()
        .map(String::as_str)
        .collect();
    let forbidden: HashSet<&str> = policy
        .forbidden_exec_paths
        .iter()
        .map(String::as_str)
        .collect();
    let mut last_seq = None;
    let mut parsed_event_count = 0usize;
    let mut digest = RollingDigest::new();
    let mut first_reject = None;
    let host_wide = summary
        .as_ref()
        .map(|summary| summary.collection_mode == "host-wide")
        .unwrap_or(false);

    for record in evidence_records {
        if record
            .raw_line
            .iter()
            .all(|byte| byte.is_ascii_whitespace())
        {
            continue;
        }

        digest.update(&record.raw_line);

        if let Some(error) = &record.parse_error {
            first_reject.get_or_insert_with(|| {
                reject_unknown_reason(format!("failed to parse evidence: {error}"), record.line_no)
            });
            continue;
        }

        let event = record.event.as_ref().expect("parsed record missing event");
        parsed_event_count += 1;

        if first_reject.is_some() {
            continue;
        }

        match last_seq {
            Some(previous) => {
                let expected = previous + 1;
                if event.seq != expected {
                    first_reject = Some(reject_reason(
                        format!(
                            "evidence sequence gap: expected seq {} got {}",
                            expected, event.seq
                        ),
                        record.line_no,
                        event,
                    ));
                    continue;
                }
            }
            None if event.seq != 1 => {
                first_reject = Some(reject_reason(
                    format!("evidence sequence must start at 1, got {}", event.seq),
                    record.line_no,
                    event,
                ));
                continue;
            }
            None => {}
        }
        last_seq = Some(event.seq);

        if event.lost != 0 {
            first_reject = Some(reject_reason(
                format!("monitor reported {} lost events", event.lost),
                record.line_no,
                event,
            ));
            continue;
        }

        if !host_wide && event.workload_id.as_deref() != Some(policy.workload_id.as_str()) {
            first_reject = Some(reject_reason("workload mismatch", record.line_no, event));
            continue;
        }

        if host_wide && event.workload_id.is_none() && !allow_host_wide {
            first_reject = Some(reject_reason(
                "host-wide evidence requires --allow-host-wide",
                record.line_no,
                event,
            ));
            continue;
        }

        let verification_event = VerificationEvent::from_event(event);
        if let Some(reason) = verify_event(
            policy,
            &allowed,
            &forbidden,
            verification_event,
            record.line_no,
        ) {
            first_reject = Some(reason);
            continue;
        }
    }

    if parsed_event_count == 0 && !allow_empty_evidence {
        return Ok(Verdict::Reject(
            "evidence file contains no events, line=<none>, workload_id=<unknown>, seq=<none>"
                .to_string(),
        ));
    }

    let evidence_digest = digest.hex();

    if let Some(summary) = summary {
        match summary.collection_mode.as_str() {
            "scoped" | "host-wide" => {}
            other => {
                return Ok(Verdict::Reject(format!(
                    "invalid collection_mode {}, line=<summary>, workload_id={}, seq=<none>",
                    other,
                    summary.workload_id.as_deref().unwrap_or("<unknown>")
                )));
            }
        }

        if summary.collection_mode != "host-wide"
            && summary.workload_id.as_deref() != Some(policy.workload_id.as_str())
        {
            return Ok(Verdict::Reject(format!(
                "workload mismatch, line=<summary>, workload_id={}, seq=<none>",
                summary.workload_id.as_deref().unwrap_or("<unknown>")
            )));
        }

        if summary.collection_mode == "host-wide" && !allow_host_wide {
            return Ok(Verdict::Reject(format!(
                "host-wide evidence requires --allow-host-wide, line=<summary>, workload_id={}, seq=<none>",
                summary.workload_id.as_deref().unwrap_or("<unknown>")
            )));
        }

        if summary.malformed_samples != 0 {
            return Ok(Verdict::Reject(format!(
                "summary reports {} malformed ringbuf samples, line=<summary>, workload_id={}, seq={}",
                summary.malformed_samples,
                summary.workload_id.as_deref().unwrap_or("<unknown>"),
                summary.final_seq
            )));
        }

        if summary.event_count != parsed_event_count {
            return Ok(Verdict::Reject(format!(
                "summary event_count mismatch: expected {} got {}, line=<summary>, workload_id={}, seq={}",
                summary.event_count,
                parsed_event_count,
                summary.workload_id.as_deref().unwrap_or("<unknown>"),
                summary.final_seq
            )));
        }

        if summary.final_lost != 0 {
            return Ok(Verdict::Reject(format!(
                "summary reports {} final lost events, line=<summary>, workload_id={}, seq={}",
                summary.final_lost,
                summary.workload_id.as_deref().unwrap_or("<unknown>"),
                summary.final_seq
            )));
        }

        let expected_final_seq = parsed_event_count as u64 + summary.final_lost;
        if summary.final_seq != expected_final_seq {
            return Ok(Verdict::Reject(format!(
                "summary final_seq mismatch: expected {} got {}, line=<summary>, workload_id={}, seq={}",
                expected_final_seq,
                summary.final_seq,
                summary.workload_id.as_deref().unwrap_or("<unknown>"),
                summary.final_seq
            )));
        }

        if last_seq != Some(summary.final_seq) {
            return Ok(Verdict::Reject(format!(
                "summary final_seq does not match last evidence seq, line=<summary>, workload_id={}, seq={}",
                summary.workload_id.as_deref().unwrap_or("<unknown>"),
                summary.final_seq
            )));
        }

        if summary.evidence_digest != evidence_digest {
            return Ok(Verdict::Reject(format!(
                "summary digest mismatch: expected {} got {}, line=<summary>, workload_id={}, seq=<none>",
                summary.evidence_digest,
                evidence_digest,
                summary.workload_id.as_deref().unwrap_or("<unknown>")
            )));
        }
    }

    if let Some(reason) = first_reject {
        return Ok(Verdict::Reject(reason));
    }

    Ok(Verdict::Accept)
}

fn load_evidence_records(path: &Path) -> Result<Vec<EvidenceRecord>> {
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut line = Vec::new();
    let mut line_no = 0usize;

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line).map_err(|e| {
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

        if line.ends_with(b"\n") {
            line.pop();
        }

        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }

        match serde_json::from_slice::<EvidenceEvent>(&line) {
            Ok(event) => records.push(EvidenceRecord::parsed(line_no, line.clone(), event)),
            Err(error) => records.push(EvidenceRecord::parse_error(
                line_no,
                line.clone(),
                error.to_string(),
            )),
        }
    }

    Ok(records)
}

fn verify(
    policy: &VerifierPolicy,
    evidence_path: &Path,
    summary_path: Option<&Path>,
    allow_host_wide: bool,
    allow_missing_summary: bool,
    allow_empty_evidence: bool,
) -> Result<Verdict> {
    if summary_path.is_none() && !allow_missing_summary {
        return Ok(Verdict::Reject(
            "summary is required; pass --summary <runtime_events.summary.json> or --allow-missing-summary for development-only verification".to_string(),
        ));
    }

    let evidence_records = load_evidence_records(evidence_path)?;
    let summary = match summary_path {
        Some(path) => Some(load_summary(path)?),
        None => None,
    };

    verify_evidence_with_options(
        policy,
        &evidence_records,
        summary.as_ref(),
        allow_host_wide,
        allow_empty_evidence,
    )
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let policy = load_policy(&args.policy)?;

    match verify(
        &policy,
        &args.evidence,
        args.summary.as_deref(),
        args.allow_host_wide,
        args.allow_missing_summary,
        args.allow_empty_evidence,
    )? {
        Verdict::Accept => {
            println!("ACCEPT: all events comply with policy");
            Ok(())
        }
        Verdict::Reject(reason) => {
            println!("REJECT: {reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify_evidence(
        policy: &VerifierPolicy,
        evidence_records: &[EvidenceRecord],
        summary: Option<&EvidenceSummary>,
        allow_host_wide: bool,
    ) -> Result<Verdict> {
        verify_evidence_with_options(policy, evidence_records, summary, allow_host_wide, false)
    }

    fn policy(default_action: &str) -> VerifierPolicy {
        VerifierPolicy {
            workload_id: "workload-a".to_string(),
            allowed_exec_paths: vec!["/usr/bin/echo".to_string()],
            forbidden_exec_paths: vec!["/usr/bin/id".to_string()],
            default_action: match default_action {
                "allow" => DefaultAction::Allow,
                "deny" => DefaultAction::Deny,
                other => panic!("invalid test default_action {other}"),
            },
        }
    }

    fn event(
        seq: u64,
        workload_id: Option<&str>,
        exe_path: &str,
        filename_read_ok: Option<bool>,
        filename_truncated: Option<bool>,
    ) -> EvidenceEvent {
        EvidenceEvent {
            seq,
            lost: 0,
            workload_id: workload_id.map(str::to_string),
            workload_index: 1,
            event_type: "exec".to_string(),
            pid: 42,
            tgid: 42,
            cgroup_id: 99,
            comm: "echo".to_string(),
            exe_path: exe_path.to_string(),
            filename_read_ok,
            filename_truncated,
            filename_read_error: None,
            ts_ns: 123,
        }
    }

    fn typed_event(event_type: &str) -> EvidenceEvent {
        let mut event = event(
            1,
            Some("workload-a"),
            "/usr/bin/not-on-the-allow-list",
            None,
            None,
        );
        event.event_type = event_type.to_string();
        event
    }

    fn record(line_no: usize, event: EvidenceEvent) -> EvidenceRecord {
        EvidenceRecord::parsed(
            line_no,
            serde_json::to_vec(&event).expect("event to serialize"),
            event,
        )
    }

    fn digest_for(records: &[EvidenceRecord]) -> String {
        let mut digest = RollingDigest::new();
        for record in records {
            digest.update(&record.raw_line);
        }
        digest.hex()
    }

    fn base_summary(records: &[EvidenceRecord]) -> EvidenceSummary {
        EvidenceSummary {
            workload_id: Some("workload-a".to_string()),
            collection_mode: "scoped".to_string(),
            event_count: records
                .iter()
                .filter(|record| record.event.is_some())
                .count(),
            evidence_digest: digest_for(records),
            final_seq: records
                .last()
                .and_then(|record| record.event.as_ref())
                .map(|event| event.seq)
                .unwrap_or(0),
            final_lost: 0,
            malformed_samples: 0,
        }
    }

    #[test]
    fn invalid_default_action_rejects_on_deserialize() {
        let json = r#"{
            "workload_id": "workload-a",
            "allowed_exec_paths": ["/usr/bin/echo"],
            "forbidden_exec_paths": ["/usr/bin/id"],
            "default_action": "denny"
        }"#;

        let parsed = serde_json::from_str::<VerifierPolicy>(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn echo_allowed_accepts() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }

    #[test]
    fn global_sequence_accepts() {
        let records = vec![
            record(
                1,
                event(
                    1,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
            record(
                2,
                event(
                    2,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
        ];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }

    #[test]
    fn fork_event_accepts_without_exec_path_policy() {
        let records = vec![record(1, typed_event("fork"))];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }

    #[test]
    fn unsupported_event_type_rejects() {
        let records = vec![record(1, typed_event("open"))];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("unsupported event_type open")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn id_forbidden_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/id",
                Some(true),
                Some(false),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("forbidden executable")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn unknown_exe_denied_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/python",
                Some(true),
                Some(false),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => {
                assert!(reason.contains("not allowed by default deny policy"))
            }
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn workload_mismatch_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("different-workload"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("workload mismatch")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn summary_workload_mismatch_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let mut summary = base_summary(&records);
        summary.workload_id = Some("different-workload".to_string());
        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("workload mismatch")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn sequence_gap_rejects() {
        let records = vec![
            record(
                1,
                event(
                    1,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
            record(
                2,
                event(
                    3,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
        ];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("evidence sequence gap")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn lost_events_reject() {
        let mut event = event(
            1,
            Some("workload-a"),
            "/usr/bin/echo",
            Some(true),
            Some(false),
        );
        event.lost = 1;
        let records = vec![record(1, event)];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("lost events")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn empty_evidence_rejects() {
        let records = Vec::new();
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("evidence file contains no events")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn filename_read_failed_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(false),
                Some(false),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("filename read failed")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn filename_read_missing_rejects() {
        let records = vec![record(
            1,
            event(1, Some("workload-a"), "/usr/bin/echo", None, Some(false)),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("filename read failed")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn filename_truncated_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(true),
            ),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("filename truncated")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn filename_truncated_missing_rejects() {
        let records = vec![record(
            1,
            event(1, Some("workload-a"), "/usr/bin/echo", Some(true), None),
        )];
        let verdict = verify_evidence(&policy("deny"), &records, None, false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("filename truncated")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn summary_digest_match_accepts() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let summary = base_summary(&records);
        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");

        match verdict {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }

    #[test]
    fn summary_digest_mismatch_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let mut summary = base_summary(&records);
        summary.evidence_digest = "deadbeef".to_string();
        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("summary digest mismatch")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn summary_event_count_mismatch_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let mut summary = base_summary(&records);
        summary.event_count = 2;
        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("summary event_count mismatch")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn summary_final_seq_mismatch_rejects() {
        let records = vec![record(
            1,
            event(
                1,
                Some("workload-a"),
                "/usr/bin/echo",
                Some(true),
                Some(false),
            ),
        )];
        let mut summary = base_summary(&records);
        summary.final_seq = 2;
        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");

        match verdict {
            Verdict::Reject(reason) => assert!(reason.contains("summary final_seq mismatch")),
            Verdict::Accept => panic!("expected reject"),
        }
    }

    #[test]
    fn host_wide_summary_requires_override() {
        let records = vec![record(
            1,
            event(1, None, "/usr/bin/echo", Some(true), Some(false)),
        )];
        let mut summary = base_summary(&records);
        summary.collection_mode = "host-wide".to_string();

        let rejected =
            verify_evidence(&policy("deny"), &records, Some(&summary), false).expect("verdict");
        match rejected {
            Verdict::Reject(reason) => {
                assert!(reason.contains("host-wide evidence requires --allow-host-wide"))
            }
            Verdict::Accept => panic!("expected reject"),
        }

        let accepted =
            verify_evidence(&policy("deny"), &records, Some(&summary), true).expect("verdict");
        match accepted {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }

    #[test]
    fn interleaved_host_wide_global_sequence_accepts() {
        let records = vec![
            record(
                1,
                event(
                    1,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
            record(
                2,
                event(
                    2,
                    Some("workload-b"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
            record(
                3,
                event(
                    3,
                    Some("workload-a"),
                    "/usr/bin/echo",
                    Some(true),
                    Some(false),
                ),
            ),
        ];
        let mut summary = base_summary(&records);
        summary.workload_id = None;
        summary.collection_mode = "host-wide".to_string();

        let verdict =
            verify_evidence(&policy("deny"), &records, Some(&summary), true).expect("verdict");

        match verdict {
            Verdict::Accept => {}
            Verdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
        }
    }
}
