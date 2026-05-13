use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow};
use num_bigint::BigUint;
use sp1_verifier::VK_ROOT_BYTES;

/// SP1 v6 standard constants. Together with the program's vkey hash they fully
/// determine the four public-input fields the verifier circuit folds into
/// `vk.gamma_abc_g1[0]` at compile time.
const SP1_V6_EXIT_CODE: &str = "0";
const SP1_V6_PROOF_NONCE: &str = "0";

pub struct CompileTimeInputs {
    pub sp1_vkey_hash: String,
    pub exit_code: String,
    pub vk_root: String,
    pub proof_nonce: String,
}

pub fn load_from_vkey_file(path: &Path) -> Result<CompileTimeInputs> {
    let bytes = fs::read(path).with_context(|| format!("failed to read vkey file {:?}", path))?;
    let vkey: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow!(
            "expected 32-byte vkey hash in {:?}, got {} bytes",
            path,
            v.len()
        )
    })?;

    Ok(CompileTimeInputs {
        sp1_vkey_hash: BigUint::from_bytes_be(&vkey).to_string(),
        exit_code: SP1_V6_EXIT_CODE.to_string(),
        vk_root: BigUint::from_bytes_be(&*VK_ROOT_BYTES).to_string(),
        proof_nonce: SP1_V6_PROOF_NONCE.to_string(),
    })
}
