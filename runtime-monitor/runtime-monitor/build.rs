use anyhow::{Context as _, anyhow, bail};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() -> anyhow::Result<()> {
    const DEFAULT_EBPF_TOOLCHAIN: &str = "nightly-2026-06-02";
    const DEFAULT_EBPF_CPU: &str = "v3";

    println!("cargo:rerun-if-env-changed=RUNTIME_MONITOR_EBPF_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=RUNTIME_MONITOR_EBPF_CPU");
    println!("cargo:rerun-if-env-changed=RUNTIME_MONITOR_EBPF_OBJECT");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");

    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR is not set"))?);

    if env::var_os("AYA_BUILD_SKIP").is_some() {
        return copy_prebuilt_ebpf_object(&out_dir);
    }

    let cargo_metadata::Metadata {
        packages,
        workspace_root,
        ..
    } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "runtime-monitor-ebpf")
        .ok_or_else(|| anyhow!("runtime-monitor-ebpf package not found"))?;

    let ebpf_package_name = ebpf_package.name.as_str();
    let ebpf_manifest_dir = ebpf_package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {}", ebpf_package.manifest_path))?;

    let ebpf_bin_name = ebpf_package
        .targets
        .iter()
        .find(|target| target.kind.contains(&cargo_metadata::TargetKind::Bin))
        .map(|target| target.name.as_str())
        .ok_or_else(|| anyhow!("runtime-monitor-ebpf has no binary target"))?;

    println!("cargo:rerun-if-changed={ebpf_manifest_dir}");

    let ebpf_toolchain = env::var("RUNTIME_MONITOR_EBPF_TOOLCHAIN")
        .unwrap_or_else(|_| DEFAULT_EBPF_TOOLCHAIN.to_owned());

    let ebpf_cpu =
        env::var("RUNTIME_MONITOR_EBPF_CPU").unwrap_or_else(|_| DEFAULT_EBPF_CPU.to_owned());

    let ebpf_target = bpf_target_for_host()?;
    let rustflags_env = target_rustflags_env_var(&ebpf_target);

    let host_arch =
        env::var("CARGO_CFG_TARGET_ARCH").context("CARGO_CFG_TARGET_ARCH is not set")?;
    let bpf_target_arch = target_arch_fixup(&host_arch);

    // -Ctarget-cpu=v3 is required because the eBPF program uses atomic_xadd
    // and consumes its return value for the global sequence counter.
    let ebpf_rustflags = format!(
        "--cfg=bpf_target_arch=\"{bpf_target_arch}\" \
         -Cdebuginfo=2 \
         -Ctarget-cpu={ebpf_cpu} \
         -Clink-arg=--btf"
    );

    let ebpf_target_dir = out_dir.join("ebpf-target");

    let mut cmd = Command::new("rustup");
    cmd.current_dir(workspace_root.as_std_path());
    cmd.args([
        "run",
        ebpf_toolchain.as_str(),
        "cargo",
        "build",
        "--package",
        ebpf_package_name,
        "--bins",
        "--release",
        "--target",
        ebpf_target.as_str(),
        "-Z",
        "build-std=core",
        "--target-dir",
    ]);
    cmd.arg(&ebpf_target_dir);

    cmd.env(&rustflags_env, &ebpf_rustflags);

    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    println!(
        "cargo:warning=building eBPF package={ebpf_package_name} \
         bin={ebpf_bin_name} toolchain={ebpf_toolchain} \
         target={ebpf_target} cpu={ebpf_cpu}"
    );

    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn nested eBPF build: {cmd:?}"))?;

    if !status.success() {
        bail!("nested eBPF build failed with status {status}");
    }

    let built_object = ebpf_target_dir
        .join(&ebpf_target)
        .join("release")
        .join(ebpf_bin_name);

    copy_ebpf_object(&built_object, &out_dir, ebpf_bin_name)?;

    Ok(())
}

fn copy_prebuilt_ebpf_object(out_dir: &Path) -> anyhow::Result<()> {
    let object = env::var_os("RUNTIME_MONITOR_EBPF_OBJECT").ok_or_else(|| {
        anyhow!("AYA_BUILD_SKIP is set but RUNTIME_MONITOR_EBPF_OBJECT is not set")
    })?;

    let object = PathBuf::from(object);
    copy_ebpf_object(&object, out_dir, "runtime-monitor")
}

fn copy_ebpf_object(src: &Path, out_dir: &Path, dst_name: &str) -> anyhow::Result<()> {
    if !src.exists() {
        bail!("eBPF object does not exist: {}", src.display());
    }

    let dst = out_dir.join(dst_name);

    fs::copy(src, &dst).with_context(|| {
        format!(
            "failed to copy eBPF object from {} to {}",
            src.display(),
            dst.display()
        )
    })?;

    println!("cargo:rerun-if-changed={}", src.display());
    println!(
        "cargo:warning=using eBPF object {} -> {}",
        src.display(),
        dst.display()
    );

    Ok(())
}

fn bpf_target_for_host() -> anyhow::Result<String> {
    let endian =
        env::var("CARGO_CFG_TARGET_ENDIAN").context("CARGO_CFG_TARGET_ENDIAN is not set")?;

    match endian.as_str() {
        "little" => Ok("bpfel-unknown-none".to_owned()),
        "big" => Ok("bpfeb-unknown-none".to_owned()),
        other => bail!("unsupported target endian: {other}"),
    }
}

fn target_rustflags_env_var(target: &str) -> String {
    format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        target.replace('-', "_").to_ascii_uppercase()
    )
}

fn target_arch_fixup(target_arch: &str) -> &str {
    if target_arch.starts_with("riscv64") {
        "riscv64"
    } else {
        target_arch
    }
}
