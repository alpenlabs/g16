use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use num_bigint::BigUint;
use sp1_verifier::VK_ROOT_BYTES;
use zkaleido::{ProofReceiptWithMetadata, ProofType, ZkVm};
use zkaleido_sp1_groth16_verifier::Sp1Groth16Proof;

/// SP1 v6 standard constants (used when only a vkey hash is supplied).
const SP1_V6_EXIT_CODE: &str = "0";
const SP1_V6_PROOF_NONCE: &str = "0";

pub struct CompileTimeInputs {
    pub sp1_vkey_hash: String,
    pub exit_code: String,
    pub vk_root: String,
    pub proof_nonce: String,
}

pub struct RunTimeInputs {
    pub gnark_compressed_proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

pub struct LoadedProof {
    pub compile_time: CompileTimeInputs,
    pub run_time: Option<RunTimeInputs>,
}

pub fn load_from_proof(path: &Path) -> Result<LoadedProof> {
    let receipt = ProofReceiptWithMetadata::load(path)
        .map_err(|e| anyhow!("failed to load proof receipt from {:?}: {e}", path))?;

    let metadata = receipt.metadata();
    if !matches!(metadata.zkvm(), ZkVm::SP1) {
        bail!("expected SP1 proof, got zkvm={:?}", metadata.zkvm());
    }
    if metadata.proof_type() != ProofType::Groth16 {
        bail!(
            "expected Groth16 proof_type, got {:?}",
            metadata.proof_type()
        );
    }

    let proof_bytes = receipt.receipt().proof().as_bytes();
    let pv_bytes = receipt.receipt().public_values().as_bytes();
    let program_id = metadata.program_id();

    let parsed = Sp1Groth16Proof::parse(proof_bytes)
        .map_err(|e| anyhow!("failed to parse SP1 Groth16 proof bytes: {e}"))?;

    let exit_code_bytes = parsed
        .exit_code
        .context("proof bytes missing exit_code prefix field")?;
    let vk_root_bytes = parsed
        .vk_root
        .context("proof bytes missing vk_root prefix field")?;
    let proof_nonce_bytes = parsed
        .proof_nonce
        .context("proof bytes missing proof_nonce prefix field")?;

    Ok(LoadedProof {
        compile_time: CompileTimeInputs {
            sp1_vkey_hash: BigUint::from_bytes_be(&program_id.0).to_string(),
            exit_code: BigUint::from_bytes_be(&exit_code_bytes).to_string(),
            vk_root: BigUint::from_bytes_be(&vk_root_bytes).to_string(),
            proof_nonce: BigUint::from_bytes_be(&proof_nonce_bytes).to_string(),
        },
        run_time: Some(RunTimeInputs {
            gnark_compressed_proof: parsed.proof.to_gnark_compressed_bytes().to_vec(),
            public_values: pv_bytes.to_vec(),
        }),
    })
}

pub fn load_from_vkey_file(path: &Path) -> Result<LoadedProof> {
    let bytes = fs::read(path).with_context(|| format!("failed to read vkey file {:?}", path))?;
    let vkey: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow!(
            "expected 32-byte vkey hash in {:?}, got {} bytes",
            path,
            v.len()
        )
    })?;

    Ok(LoadedProof {
        compile_time: CompileTimeInputs {
            sp1_vkey_hash: BigUint::from_bytes_be(&vkey).to_string(),
            exit_code: SP1_V6_EXIT_CODE.to_string(),
            vk_root: BigUint::from_bytes_be(&*VK_ROOT_BYTES).to_string(),
            proof_nonce: SP1_V6_PROOF_NONCE.to_string(),
        },
        run_time: None,
    })
}
