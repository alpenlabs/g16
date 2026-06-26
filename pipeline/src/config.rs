use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow};
use ark_serialize::CanonicalSerialize;
use serde_json::json;
use sp1_verifier::{GROTH16_VK_BYTES, load_ark_groth16_verifying_key_from_bytes};

use crate::proof::{CompileTimeInputs, RunTimeInputs};

pub fn write_compile_time_json(out_path: &Path, compile: &CompileTimeInputs) -> Result<()> {
    let ark_vk = load_ark_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES)
        .map_err(|e| anyhow!("failed to parse SP1 Groth16 VK: {e:?}"))?;
    let mut vk_bytes = Vec::with_capacity(ark_vk.serialized_size(ark_serialize::Compress::Yes));
    ark_vk
        .serialize_compressed(&mut vk_bytes)
        .context("failed to ark-serialize Groth16 VK")?;

    let json = json!({
        "groth16_vk_bytes": vk_bytes,
        "sp1_vkey_hash": compile.sp1_vkey_hash,
        "exit_code": compile.exit_code,
        "vk_root": compile.vk_root,
        "proof_nonce": compile.proof_nonce,
    });

    fs::write(out_path, serde_json::to_vec_pretty(&json)?)
        .with_context(|| format!("failed to write {:?}", out_path))?;
    Ok(())
}

pub fn write_run_time_json(out_path: &Path, run: &RunTimeInputs) -> Result<()> {
    let json = json!({
        "groth16_proof": run.gnark_compressed_proof,
        "raw_public_input": run.public_values,
    });

    fs::write(out_path, serde_json::to_vec_pretty(&json)?)
        .with_context(|| format!("failed to write {:?}", out_path))?;
    Ok(())
}
