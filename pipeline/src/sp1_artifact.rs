//! Decoder for a raw SP1 v6 prover artifact (a bincode-serialized
//! `SP1ProofWithPublicValues`, or its prover-network sibling `ProofFromNetwork`).
//!
//! We deliberately avoid depending on `sp1-sdk`: it would pull in ~200 crates
//! (`sp1-prover`, `sp1-core-machine`, `sp1-recursion-*`, etc.) and force a
//! `sp1-verifier 6.2.x` resolution that conflicts with the `=6.1.0` we pin
//! elsewhere in this workspace. Instead, we mirror just enough of the bincode
//! field layout to recover the Groth16 proof bytes and public values.

use std::{fs::File, io::BufReader, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use zkaleido_sp1_groth16_verifier::Sp1Groth16Proof;

use crate::proof::RunTimeInputs;

/// `SP1Proof` is `#[derive(Serialize, Deserialize)]` with the default
/// declaration order: `Core, Compressed, Plonk, Groth16`. Bincode encodes the
/// variant as a little-endian `u32`, so Groth16 is tag 3.
const SP1_PROOF_GROTH16_TAG: u32 = 3;

/// Mirror of `sp1_verifier::Groth16Bn254Proof`. Bincode is positional, so field
/// names are irrelevant — only the declaration order matters.
#[allow(dead_code)]
#[derive(Deserialize)]
struct Groth16Bn254ProofMirror {
    public_inputs: [String; 5],
    /// This is the field `SP1ProofWithPublicValues::bytes()` uses to build
    /// the on-chain proof blob — it's the prefix-tagged Groth16 proof bytes
    /// (the form `Sp1Groth16Proof::parse` accepts), hex-encoded as a string.
    encoded_proof: String,
    raw_proof: String,
    groth16_vkey_hash: [u8; 32],
}

/// Mirror of `sp1_primitives::types::Buffer`. `ptr` is `#[serde(skip)]`
/// upstream, so the on-disk encoding is just `{ data: Vec<u8> }`.
#[derive(Deserialize)]
struct BufferMirror {
    data: Vec<u8>,
}

/// Mirror of `sp1_primitives::io::SP1PublicValues`.
#[derive(Deserialize)]
struct SP1PublicValuesMirror {
    buffer: BufferMirror,
}

/// Decode a raw SP1 v6 artifact at `path` and lift it into [`RunTimeInputs`].
/// Errors loudly if the artifact is not a Groth16 proof.
pub fn load_runtime_from_sp1_artifact(path: &Path) -> Result<RunTimeInputs> {
    let file =
        File::open(path).with_context(|| format!("failed to open SP1 artifact {:?}", path))?;
    let mut reader = BufReader::new(file);

    let tag: u32 = bincode::deserialize_from(&mut reader)
        .with_context(|| format!("failed to read SP1Proof discriminant from {:?}", path))?;
    if tag != SP1_PROOF_GROTH16_TAG {
        let mode = match tag {
            0 => "Core",
            1 => "Compressed",
            2 => "Plonk",
            other => return Err(anyhow!("SP1Proof variant tag {other} is not a known mode")),
        };
        bail!(
            "SP1 artifact {:?} is a {} proof; only Groth16 is supported",
            path,
            mode,
        );
    }

    let groth16: Groth16Bn254ProofMirror = bincode::deserialize_from(&mut reader)
        .with_context(|| format!("failed to decode Groth16Bn254Proof in {:?}", path))?;
    let public_values: SP1PublicValuesMirror = bincode::deserialize_from(&mut reader)
        .with_context(|| format!("failed to decode SP1PublicValues in {:?}", path))?;
    // `sp1_version` and (for the post-network format) `tee_proof` trail this
    // point; we don't need them.

    // Reconstruct what `SP1ProofWithPublicValues::bytes()` returns for the
    // Groth16 variant: the first 4 bytes of the groth16 vkey hash (used as the
    // on-chain selector) followed by the hex-decoded encoded proof.
    let encoded = hex::decode(&groth16.encoded_proof)
        .context("failed to hex-decode Groth16 encoded_proof")?;
    let mut proof_bytes = Vec::with_capacity(4 + encoded.len());
    proof_bytes.extend_from_slice(&groth16.groth16_vkey_hash[..4]);
    proof_bytes.extend_from_slice(&encoded);

    let parsed = Sp1Groth16Proof::parse(&proof_bytes)
        .map_err(|e| anyhow!("failed to parse SP1 Groth16 proof bytes: {e}"))?;

    Ok(RunTimeInputs {
        gnark_compressed_proof: parsed.proof.to_gnark_compressed_bytes().to_vec(),
        public_values: public_values.buffer.data,
    })
}
