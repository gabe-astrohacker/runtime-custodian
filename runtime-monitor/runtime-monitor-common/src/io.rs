//! Userspace-only filesystem/serde IO helpers shared by the verifier and
//! trainer binaries. Gated behind the `user` feature alongside the rest of the
//! std/serde_json userspace surface so the `no_std` eBPF consumer never pulls
//! these in.

use crate::EvidenceRecord;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::string::String;
use std::vec::Vec;

pub fn load_json<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let file =
        File::open(path).map_err(|e| anyhow!("failed to open {label} {}: {e}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|e| anyhow!("failed to parse {label} {}: {e}", path.display()))
}

pub fn load_evidence_records(path: &Path) -> Result<Vec<EvidenceRecord>> {
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

pub fn record_session_id(record: &EvidenceRecord) -> &str {
    match record {
        EvidenceRecord::RuntimeEvent(event) => &event.session_id,
        EvidenceRecord::Synthetic(record) => &record.session_id,
    }
}

pub fn write_json_pretty<T>(path: &Path, value: &T, label: &str) -> Result<()>
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
    let mut writer = BufWriter::new(file);

    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|e| anyhow!("failed to write {label} {}: {e}", path.display()))?;

    writer
        .flush()
        .map_err(|e| anyhow!("failed to flush {label} {}: {e}", path.display()))
}
