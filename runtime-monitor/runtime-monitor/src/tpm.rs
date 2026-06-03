#![allow(dead_code)]

use anyhow::{Result, anyhow};
use std::process::{Command, Output};

use runtime_monitor_common::{AttestationPolicy, EventClassification};

const SUPPORTED_HASH_BANK: &str = "sha256";
const SUPPORTED_MODES: &[&str] = &["software-chain", "final-summary", "policy-triggered"];
const MAX_PCR_INDEX: u32 = 23;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TpmLocalOptions {
    pub tcti: Option<String>,
    pub reset_pcr: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    pub enabled: bool,
    pub tcti: Option<String>,
    pub mode: String,
    pub hash_bank: String,
    pub runtime_pcr: Option<u32>,
    pub reset_pcr: bool,
    pub extend_on: Vec<EventClassification>,
    pub fail_on_tpm_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrValue {
    pub pcr: u32,
    pub hash_bank: String,
    pub digest_hex: String,
}

pub trait TpmCommandRunner {
    fn run(&self, program: &str, args: &[String], envs: &[(&str, &str)]) -> Result<Output>;
}

#[allow(dead_code)]
pub struct SystemTpmCommandRunner;

impl TpmCommandRunner for SystemTpmCommandRunner {
    fn run(&self, program: &str, args: &[String], envs: &[(&str, &str)]) -> Result<Output> {
        let mut command = Command::new(program);
        command.args(args);
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow!("TPM tool `{program}` is not available")
            } else {
                anyhow!("failed to run TPM tool `{program}`: {error}")
            }
        })
    }
}

impl TpmConfig {
    pub fn from_policy_and_local_options(
        policy: &AttestationPolicy,
        local: TpmLocalOptions,
    ) -> Result<Self> {
        let backend = normalize_field(&policy.backend, "attestation.backend")?;
        let mode = validate_mode(&policy.mode)?;
        let extend_on = validate_extend_on(&policy.extend_on, &backend, &mode)?;
        let tcti = normalize_optional_local_string(local.tcti);
        let reset_pcr = local.reset_pcr;

        match backend.as_str() {
            "none" => Ok(Self {
                enabled: false,
                tcti,
                mode,
                hash_bank: default_hash_bank(policy),
                runtime_pcr: None,
                reset_pcr,
                extend_on,
                fail_on_tpm_error: policy.fail_on_tpm_error.unwrap_or(false),
            }),
            "tpm" => {
                let hash_bank = validate_hash_bank(policy.hash_bank.as_deref())?;
                let runtime_pcr = policy.runtime_pcr.ok_or_else(|| {
                    anyhow!("attestation.runtime_pcr is required when backend is `tpm`")
                })?;
                let runtime_pcr = validate_pcr(runtime_pcr, "attestation.runtime_pcr")?;

                Ok(Self {
                    enabled: true,
                    tcti,
                    mode,
                    hash_bank,
                    runtime_pcr: Some(runtime_pcr),
                    reset_pcr,
                    extend_on,
                    fail_on_tpm_error: policy.fail_on_tpm_error.unwrap_or(true),
                })
            }
            _ => Err(anyhow!(
                "unsupported attestation.backend `{}`; expected `none` or `tpm`",
                policy.backend
            )),
        }
    }

    pub fn is_policy_triggered(&self) -> bool {
        self.enabled && self.mode == "policy-triggered"
    }

    pub fn should_extend_classification(&self, classification: EventClassification) -> bool {
        self.is_policy_triggered() && self.extend_on.contains(&classification)
    }

    fn runtime_pcr_for_command(&self, operation: &str) -> Result<u32> {
        self.ensure_enabled(operation)?;
        self.runtime_pcr
            .ok_or_else(|| anyhow!("cannot {operation}: TPM runtime PCR is not configured"))
    }

    fn reset_pcr_for_command(&self, operation: &str) -> Result<u32> {
        self.ensure_enabled(operation)?;
        if !self.reset_pcr {
            return Err(anyhow!(
                "cannot {operation}: TPM PCR reset is disabled by local config"
            ));
        }
        self.runtime_pcr
            .ok_or_else(|| anyhow!("cannot {operation}: TPM runtime PCR is not configured"))
    }

    fn ensure_enabled(&self, operation: &str) -> Result<()> {
        if !self.enabled {
            return Err(anyhow!("cannot {operation}: TPM backend is disabled"));
        }
        Ok(())
    }
}

pub fn pcr_read<R>(runner: &R, config: &TpmConfig) -> Result<PcrValue>
where
    R: TpmCommandRunner,
{
    let pcr = config.runtime_pcr_for_command("read PCR")?;
    let args = vec![format!("{}:{pcr}", config.hash_bank)];
    let output = run_checked(runner, config, "tpm2_pcrread", args)?;
    let digest_hex = parse_pcr_read_output(&output.stdout, pcr)?;

    Ok(PcrValue {
        pcr,
        hash_bank: config.hash_bank.clone(),
        digest_hex,
    })
}

pub fn pcr_reset<R>(runner: &R, config: &TpmConfig) -> Result<()>
where
    R: TpmCommandRunner,
{
    let pcr = config.reset_pcr_for_command("reset PCR")?;
    let args = vec![pcr.to_string()];
    run_checked(runner, config, "tpm2_pcrreset", args)?;
    Ok(())
}

pub fn pcr_extend<R>(runner: &R, config: &TpmConfig, digest_hex: &str) -> Result<()>
where
    R: TpmCommandRunner,
{
    let pcr = config.runtime_pcr_for_command("extend PCR")?;
    let digest_hex = validate_sha256_digest_hex(digest_hex)?;
    let args = vec![format!("{pcr}:{}={digest_hex}", config.hash_bank)];
    run_checked(runner, config, "tpm2_pcrextend", args)?;
    Ok(())
}

fn run_checked<R>(
    runner: &R,
    config: &TpmConfig,
    program: &str,
    args: Vec<String>,
) -> Result<Output>
where
    R: TpmCommandRunner,
{
    let mut envs = Vec::new();
    if let Some(tcti) = config.tcti.as_deref() {
        envs.push(("TPM2TOOLS_TCTI", tcti));
    }

    let output = runner.run(program, &args, &envs)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "TPM tool `{program}` failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(output)
}

fn parse_pcr_read_output(stdout: &[u8], pcr: u32) -> Result<String> {
    let output = String::from_utf8_lossy(stdout);
    let pcr_label = pcr.to_string();

    for line in output.lines() {
        let trimmed = line.trim();
        let Some((candidate_pcr, digest)) = trimmed.split_once(':') else {
            continue;
        };
        if candidate_pcr.trim() == pcr_label {
            return validate_sha256_digest_hex(digest.trim());
        }
    }

    Err(anyhow!("tpm2_pcrread output did not contain PCR {pcr}"))
}

fn validate_mode(mode: &str) -> Result<String> {
    let mode = normalize_field(mode, "attestation.mode")?;
    if SUPPORTED_MODES.contains(&mode.as_str()) {
        return Ok(mode);
    }
    Err(anyhow!(
        "unsupported attestation.mode `{mode}`; expected one of {}",
        SUPPORTED_MODES.join(", ")
    ))
}

fn validate_extend_on(
    values: &[String],
    backend: &str,
    mode: &str,
) -> Result<Vec<EventClassification>> {
    let mut extend_on = Vec::new();
    for value in values {
        let value = normalize_field(value, "attestation.extend_on")?;
        let classification = match value.as_str() {
            "acceptable" => EventClassification::Acceptable,
            "suspicious" => EventClassification::Suspicious,
            "denied" => EventClassification::Denied,
            _ => {
                return Err(anyhow!(
                    "unsupported attestation.extend_on value `{value}`; expected one of acceptable, suspicious, denied"
                ));
            }
        };

        if extend_on.contains(&classification) {
            return Err(anyhow!(
                "duplicate attestation.extend_on value `{value}` is not allowed"
            ));
        }
        extend_on.push(classification);
    }

    if !extend_on.is_empty() && (backend != "tpm" || mode != "policy-triggered") {
        return Err(anyhow!(
            "attestation.extend_on is only supported when backend is `tpm` and mode is `policy-triggered`"
        ));
    }

    if backend == "tpm" && mode == "policy-triggered" && extend_on.is_empty() {
        return Err(anyhow!(
            "attestation.extend_on must not be empty when backend is `tpm` and mode is `policy-triggered`"
        ));
    }

    Ok(extend_on)
}

fn default_hash_bank(policy: &AttestationPolicy) -> String {
    policy
        .hash_bank
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(SUPPORTED_HASH_BANK)
        .to_ascii_lowercase()
}

fn validate_hash_bank(hash_bank: Option<&str>) -> Result<String> {
    let hash_bank = hash_bank
        .map(|value| normalize_field(value, "attestation.hash_bank"))
        .transpose()?
        .unwrap_or_else(|| SUPPORTED_HASH_BANK.to_owned());

    if hash_bank == SUPPORTED_HASH_BANK {
        return Ok(hash_bank);
    }

    Err(anyhow!(
        "unsupported attestation.hash_bank `{hash_bank}`; only `{SUPPORTED_HASH_BANK}` is supported"
    ))
}

fn validate_pcr(pcr: u32, field: &str) -> Result<u32> {
    if pcr <= MAX_PCR_INDEX {
        return Ok(pcr);
    }
    Err(anyhow!(
        "{field} must be in range 0..={MAX_PCR_INDEX}, got {pcr}"
    ))
}

fn validate_sha256_digest_hex(digest_hex: &str) -> Result<String> {
    let digest_hex = digest_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| digest_hex.trim());
    if digest_hex.len() != 64 || !digest_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "expected a 64-character SHA-256 hex digest, got `{digest_hex}`"
        ));
    }
    Ok(digest_hex.to_ascii_lowercase())
}

fn normalize_field(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("{field} must not be empty"));
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_optional_local_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_monitor_common::{RuntimePolicy, policy_hash};
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCall {
        program: String,
        args: Vec<String>,
        envs: Vec<(String, String)>,
    }

    #[derive(Debug)]
    struct MockRunner {
        calls: RefCell<Vec<MockCall>>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        status_raw: i32,
    }

    impl MockRunner {
        fn success(stdout: &str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
                status_raw: 0,
            }
        }

        fn calls(&self) -> Vec<MockCall> {
            self.calls.borrow().clone()
        }
    }

    impl TpmCommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[String], envs: &[(&str, &str)]) -> Result<Output> {
            self.calls.borrow_mut().push(MockCall {
                program: program.to_owned(),
                args: args.to_vec(),
                envs: envs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            });
            Ok(Output {
                status: ExitStatus::from_raw(self.status_raw),
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }

    fn tpm_policy() -> AttestationPolicy {
        AttestationPolicy {
            backend: String::from("tpm"),
            runtime_pcr: Some(23),
            hash_bank: Some(String::from("sha256")),
            ..AttestationPolicy::default()
        }
    }

    fn enabled_config() -> TpmConfig {
        TpmConfig::from_policy_and_local_options(&tpm_policy(), TpmLocalOptions::default())
            .expect("tpm config")
    }

    fn digest_hex() -> String {
        String::from("ab").repeat(32)
    }

    #[test]
    fn backend_none_disables_tpm_without_runtime_pcr() {
        let config = TpmConfig::from_policy_and_local_options(
            &AttestationPolicy::default(),
            TpmLocalOptions::default(),
        )
        .expect("config");

        assert!(!config.enabled);
        assert_eq!(config.runtime_pcr, None);
        assert_eq!(config.mode, "software-chain");
        assert_eq!(config.hash_bank, "sha256");
        assert!(config.extend_on.is_empty());
    }

    #[test]
    fn backend_tpm_with_pcr_and_hash_bank_enables_tpm() {
        let config = enabled_config();

        assert!(config.enabled);
        assert_eq!(config.runtime_pcr, Some(23));
        assert_eq!(config.mode, "software-chain");
        assert_eq!(config.hash_bank, "sha256");
        assert!(config.extend_on.is_empty());
        assert!(config.fail_on_tpm_error);
    }

    #[test]
    fn known_attestation_modes_are_accepted_for_tpm_backend() {
        for mode in SUPPORTED_MODES {
            let mut policy = tpm_policy();
            policy.mode = (*mode).to_owned();
            if *mode == "policy-triggered" {
                policy.extend_on = vec![String::from("suspicious")];
            }

            let config =
                TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
                    .expect("known mode");

            assert!(config.enabled);
        }
    }

    #[test]
    fn final_summary_mode_allows_empty_extend_on() {
        let mut policy = tpm_policy();
        policy.mode = String::from("final-summary");

        let config = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect("final summary mode");

        assert!(config.enabled);
        assert_eq!(config.mode, "final-summary");
        assert!(config.extend_on.is_empty());
    }

    #[test]
    fn policy_triggered_mode_requires_extend_on() {
        let mut policy = tpm_policy();
        policy.mode = String::from("policy-triggered");

        let error = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect_err("empty extend_on should fail");

        assert!(error.to_string().contains("extend_on"));
    }

    #[test]
    fn policy_triggered_mode_accepts_supported_extend_on_values() {
        let mut policy = tpm_policy();
        policy.mode = String::from("policy-triggered");
        policy.extend_on = vec![
            String::from("suspicious"),
            String::from("denied"),
            String::from("acceptable"),
        ];

        let config = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect("policy triggered config");

        assert_eq!(
            config.extend_on,
            vec![
                EventClassification::Suspicious,
                EventClassification::Denied,
                EventClassification::Acceptable,
            ]
        );
        assert!(config.should_extend_classification(EventClassification::Suspicious));
        assert!(config.should_extend_classification(EventClassification::Denied));
        assert!(config.should_extend_classification(EventClassification::Acceptable));
    }

    #[test]
    fn non_empty_extend_on_is_rejected_unless_policy_triggered_tpm() {
        let mut final_summary_policy = tpm_policy();
        final_summary_policy.mode = String::from("final-summary");
        final_summary_policy.extend_on = vec![String::from("suspicious")];

        let error = TpmConfig::from_policy_and_local_options(
            &final_summary_policy,
            TpmLocalOptions::default(),
        )
        .expect_err("extend_on should fail in final-summary mode");
        assert!(error.to_string().contains("policy-triggered"));

        let mut disabled_policy = AttestationPolicy {
            extend_on: vec![String::from("suspicious")],
            mode: String::from("policy-triggered"),
            ..AttestationPolicy::default()
        };
        disabled_policy.backend = String::from("none");

        let error =
            TpmConfig::from_policy_and_local_options(&disabled_policy, TpmLocalOptions::default())
                .expect_err("extend_on should fail when backend is disabled");
        assert!(error.to_string().contains("backend"));
    }

    #[test]
    fn unknown_or_duplicate_extend_on_values_are_rejected() {
        let mut unknown = tpm_policy();
        unknown.mode = String::from("policy-triggered");
        unknown.extend_on = vec![String::from("critical")];

        let error = TpmConfig::from_policy_and_local_options(&unknown, TpmLocalOptions::default())
            .expect_err("unknown extend_on should fail");
        assert!(error.to_string().contains("extend_on"));

        let mut duplicate = tpm_policy();
        duplicate.mode = String::from("policy-triggered");
        duplicate.extend_on = vec![String::from("denied"), String::from("denied")];

        let error =
            TpmConfig::from_policy_and_local_options(&duplicate, TpmLocalOptions::default())
                .expect_err("duplicate extend_on should fail");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn missing_runtime_pcr_with_tpm_backend_is_rejected() {
        let mut policy = tpm_policy();
        policy.runtime_pcr = None;

        let error = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect_err("missing pcr should fail");

        assert!(error.to_string().contains("runtime_pcr"));
    }

    #[test]
    fn unsupported_hash_bank_is_rejected_for_tpm_backend() {
        let mut policy = tpm_policy();
        policy.hash_bank = Some(String::from("sha1"));

        let error = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect_err("unsupported hash bank should fail");

        assert!(error.to_string().contains("hash_bank"));
    }

    #[test]
    fn invalid_runtime_pcr_is_rejected() {
        let mut policy = tpm_policy();
        policy.runtime_pcr = Some(24);

        let error = TpmConfig::from_policy_and_local_options(&policy, TpmLocalOptions::default())
            .expect_err("invalid pcr should fail");

        assert!(error.to_string().contains("0..=23"));
    }

    #[test]
    fn pcr_extend_uses_expected_command() {
        let runner = MockRunner::success("");
        let config = enabled_config();

        pcr_extend(&runner, &config, &digest_hex()).expect("extend");

        assert_eq!(
            runner.calls(),
            vec![MockCall {
                program: String::from("tpm2_pcrextend"),
                args: vec![format!("23:sha256={}", digest_hex())],
                envs: Vec::new(),
            }]
        );
    }

    #[test]
    fn pcr_read_uses_expected_command_and_parses_digest() {
        let digest = digest_hex();
        let stdout = format!("sha256:\n  23: 0x{digest}\n");
        let runner = MockRunner::success(&stdout);
        let config = enabled_config();

        let value = pcr_read(&runner, &config).expect("read");

        assert_eq!(
            value,
            PcrValue {
                pcr: 23,
                hash_bank: String::from("sha256"),
                digest_hex: digest,
            }
        );
        assert_eq!(
            runner.calls(),
            vec![MockCall {
                program: String::from("tpm2_pcrread"),
                args: vec![String::from("sha256:23")],
                envs: Vec::new(),
            }]
        );
    }

    #[test]
    fn pcr_reset_uses_configured_runtime_pcr_when_enabled() {
        let runner = MockRunner::success("");
        let mut policy = tpm_policy();
        policy.runtime_pcr = Some(17);
        let config = TpmConfig::from_policy_and_local_options(
            &policy,
            TpmLocalOptions {
                reset_pcr: true,
                ..TpmLocalOptions::default()
            },
        )
        .expect("config");

        pcr_reset(&runner, &config).expect("reset");

        assert_eq!(
            runner.calls(),
            vec![MockCall {
                program: String::from("tpm2_pcrreset"),
                args: vec![String::from("17")],
                envs: Vec::new(),
            }]
        );
    }

    #[test]
    fn tcti_env_is_passed_to_command_runner() {
        let digest = digest_hex();
        let stdout = format!("sha256:\n  23: 0x{digest}\n");
        let runner = MockRunner::success(&stdout);
        let config = TpmConfig::from_policy_and_local_options(
            &tpm_policy(),
            TpmLocalOptions {
                tcti: Some(String::from("swtpm:host=localhost,port=2321")),
                ..TpmLocalOptions::default()
            },
        )
        .expect("config");

        pcr_read(&runner, &config).expect("read");

        assert_eq!(
            runner.calls()[0].envs,
            vec![(
                String::from("TPM2TOOLS_TCTI"),
                String::from("swtpm:host=localhost,port=2321")
            )]
        );
    }

    #[test]
    fn pcr_helpers_reject_disabled_or_missing_pcr_config() {
        let runner = MockRunner::success("");
        let disabled = TpmConfig::from_policy_and_local_options(
            &AttestationPolicy::default(),
            TpmLocalOptions::default(),
        )
        .expect("disabled");
        let reset_disabled = enabled_config();

        assert!(pcr_extend(&runner, &disabled, &digest_hex()).is_err());
        assert!(pcr_read(&runner, &disabled).is_err());
        assert!(pcr_reset(&runner, &reset_disabled).is_err());
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn local_tpm_options_do_not_change_policy_hash() {
        let policy = RuntimePolicy {
            attestation: tpm_policy(),
            ..RuntimePolicy::default()
        };
        let before = policy_hash(&policy);

        let _config = TpmConfig::from_policy_and_local_options(
            &policy.attestation,
            TpmLocalOptions {
                tcti: Some(String::from("device:/dev/tpmrm0")),
                reset_pcr: true,
            },
        )
        .expect("config");

        assert_eq!(before, policy_hash(&policy));
    }
}
