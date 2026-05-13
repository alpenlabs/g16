use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};

fn g16_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("g16 workspace root")
        .join("Cargo.toml")
}

pub fn run_g16gen(subcommand: &str, config_path: &Path, cwd: &Path) -> Result<()> {
    let manifest = g16_manifest();
    let config_arg = config_path
        .to_str()
        .context("config path is not valid UTF-8")?
        .to_string();
    let manifest_arg = manifest
        .to_str()
        .context("manifest path is not valid UTF-8")?
        .to_string();

    let status = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--manifest-path",
            &manifest_arg,
            "-p",
            "g16gen",
            "--release",
            "--",
            subcommand,
            &config_arg,
        ])
        .current_dir(cwd)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to spawn `cargo run -p g16gen -- {subcommand}`"))?;

    if !status.success() {
        bail!("`cargo run -p g16gen -- {subcommand}` exited with {status}");
    }
    Ok(())
}

pub async fn prealloc_v5c(v5a: &Path, v5c: &Path) -> Result<()> {
    let v5a_s = v5a
        .to_str()
        .context("v5a path is not valid UTF-8")?
        .to_string();
    let v5c_s = v5c
        .to_str()
        .context("v5c path is not valid UTF-8")?
        .to_string();
    ckt_lvl::prealloc::prealloc(&v5a_s, &v5c_s).await;
    Ok(())
}

pub async fn sanity_check(v5c: &Path, inputs: &Path) -> Result<()> {
    let v5c_s = v5c
        .to_str()
        .context("v5c path is not valid UTF-8")?
        .to_string();
    let inputs_s = inputs
        .to_str()
        .context("inputs path is not valid UTF-8")?
        .to_string();

    let outputs = gobbletest::exec::exec(&v5c_s, &inputs_s).await;
    if outputs.len() != 1 {
        return Err(anyhow!(
            "expected single output bit from verifier circuit, got {} bits: {:?}",
            outputs.len(),
            outputs
        ));
    }
    if !outputs[0] {
        return Err(anyhow!(
            "verifier circuit rejected the proof (output bit = false)"
        ));
    }
    Ok(())
}
