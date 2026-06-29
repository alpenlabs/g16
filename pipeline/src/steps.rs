use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

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

/// Write a tiny but structurally valid v5c circuit (same magic/header/block/checksum
/// layout as a real run) so downstream tooling has a `v5c.ckt` to consume without paying
/// for the heavy g16gen + prealloc stages. `memo` carries the 32-byte SP1 vkey hash so the
/// dummy file still passes `verify`'s vkey-match check.
pub async fn mock_v5c(v5c: &Path, memo: [u8; 32]) -> Result<()> {
    use ckt_fmtv5_types::{
        GateType,
        v5::c::{GateV5c, WriterV5c},
    };

    let path = v5c.to_str().context("v5c path is not valid UTF-8")?;
    let mut w = WriterV5c::new(path, /* primary_inputs */ 2, /* num_outputs */ 1, memo)
        .await
        .context("failed to create v5c writer")?;
    w.write_gate(GateV5c::new(0, 1, 2), GateType::XOR).await?;
    w.write_gate(GateV5c::new(2, 1, 3), GateType::XOR).await?;
    w.write_gate(GateV5c::new(0, 2, 4), GateType::AND).await?;
    w.write_gate(GateV5c::new(3, 4, 5), GateType::AND).await?;
    w.finalize(/* scratch_space */ 1024, /* outputs */ vec![5])
        .await
        .context("failed to finalize v5c")?;
    Ok(())
}

pub async fn verify(v5a: &Path) -> Result<bool> {
    let result = ckt_fmtv5_types::v5::a::reader::verify_v5a_checksum(v5a).await;

    if result.is_err() {
        bail!("verification could not be completed");
    } else {
        Ok(result.unwrap())
    }
}
