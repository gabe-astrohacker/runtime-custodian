use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierPolicy {
    workload_id: String,
    allowed_exec_paths: Vec<String>,
    forbidden_exec_paths: Vec<String>,
    default_action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EvidenceEvent {
    workload_id: String,
    workload_index: u32,
    event_type: String,
    pid: u32,
    tgid: u32,
    cgroup_id: u64,
    comm: String,
    exe_path: String,
    filename_read_ok: bool,
    filename_truncated: bool,
    filename_read_error: Option<i32>,
    ts_ns: u64,
}

struct Args {
    policy: PathBuf,
    evidence: PathBuf,
}

enum Verdict {
    Accept,
    Reject(String),
}

fn parse_args() -> Result<Args> {
    let mut policy = None;
    let mut evidence = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => policy = args.next().map(PathBuf::from),
            "--evidence" => evidence = args.next().map(PathBuf::from),
            _ => {
                return Err(anyhow!(
                    "unknown argument `{arg}`; usage: runtime-verifier --policy <policy.json> --evidence <events.jsonl>"
                ));
            }
        }
    }

    Ok(Args {
        policy: policy.ok_or_else(|| anyhow!("missing --policy <policy.json>"))?,
        evidence: evidence.ok_or_else(|| anyhow!("missing --evidence <events.jsonl>"))?,
    })
}

fn load_policy(path: &Path) -> Result<VerifierPolicy> {
    let file = File::open(path).map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse policy {}: {e}", path.display()))
}

fn verify(policy: &VerifierPolicy, evidence_path: &Path) -> Result<Verdict> {
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

    let file = File::open(evidence_path)
        .map_err(|e| anyhow!("failed to open {}: {e}", evidence_path.display()))?;
    let reader = BufReader::new(file);

    for (index, line) in reader.lines().enumerate() {
        let line_no = index + 1;
        let line = line.map_err(|e| {
            anyhow!(
                "failed to read evidence {} at line {}: {e}",
                evidence_path.display(),
                line_no
            )
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let event: EvidenceEvent = serde_json::from_str(&line).map_err(|e| {
            anyhow!(
                "failed to parse evidence {} at line {}: {e}",
                evidence_path.display(),
                line_no
            )
        })?;

        if event.workload_id != policy.workload_id {
            return Ok(Verdict::Reject(format!(
                "workload mismatch {} at line {}",
                event.workload_id, line_no
            )));
        }

        if !event.filename_read_ok {
            let detail = event
                .filename_read_error
                .map(|error| format!(" error {error}"))
                .unwrap_or_default();
            return Ok(Verdict::Reject(format!(
                "filename read failed{} at line {}",
                detail, line_no
            )));
        }

        if forbidden.contains(event.exe_path.as_str()) {
            return Ok(Verdict::Reject(format!(
                "forbidden executable {} at line {}",
                event.exe_path, line_no
            )));
        }

        if policy.default_action == "deny" && !allowed.contains(event.exe_path.as_str()) {
            return Ok(Verdict::Reject(format!(
                "executable {} not allowed by default deny policy at line {}",
                event.exe_path, line_no
            )));
        }
    }

    Ok(Verdict::Accept)
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let policy = load_policy(&args.policy)?;

    match verify(&policy, &args.evidence)? {
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
