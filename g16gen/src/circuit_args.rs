use std::{fs, path::PathBuf};

use g16ckt::{
    ark::{CurveGroup, ark_serialize::CanonicalDeserialize},
    gadgets::{
        bigint::BigUint,
        groth16::{Groth16VerifyCompressedRawInput, ProofType},
        hash::blake3::InputMessage,
    },
};
use serde::Deserialize;

/// Size of raw input message
/// Raw input is concatenation of multiple serialized fields (say deposit index and operator pub key)
/// How the values are serialized and ordered depends upon the host program
/// For SP1, `SP1ProofWithPublicValues::public_values` holds this value from which we can obtain it
const INPUT_MESSAGE_LEN: usize = 36;
/// Size of Compressed Groth16 Proof
/// SP1 represents groth16 proof in gnark format (128 bytes total) with an extra 4 bytes of groth16 vkey hash prepended.
/// We do not require the 4 bytes of prepended vkey hash and as such do not consider it.
const COMPRESSED_PROOF_SIZE: usize = 128;
/// We use default proof type of GNARK
/// This dictates how the `RunTimeData::groth16_proof` is deserialized
const DEFAULT_PROOF_TYPE: ProofType = ProofType::GNARK;

/// Parameters required to generate binary circuit
/// Example in example_config/compile_time.json
#[derive(Debug, Deserialize)]
pub(crate) struct CompileTimeData {
    /// Groth16 Verification Key
    /// We use `ark_groth16::VerifyingKey` to deserialize the byte array,
    /// so the byte array should be in matching serialized format.
    /// In the context of proof generated from zkvm, groth16_vk remains same
    /// irrespective of any changes to host program
    groth16_vk_bytes: Vec<u8>,
    /// SP1 Verification Key Hash (public input index 1)
    /// Represents commitment of host program
    /// This field is specific to SP1 ZKVM, other zkvm's could use one or more
    /// of such fields which are known in compile time.
    /// This field is used as input by sp1's groth16 verifier, which is host program agnostic
    sp1_vkey_hash: String,
    /// Exit code (public input index 3) - SP1 v6 constant, typically "0"
    exit_code: String,
    /// VK root (public input index 4) - SP1 v6 constant
    vk_root: String,
    /// Proof nonce (public input index 5) - SP1 v6 constant, typically "0"
    proof_nonce: String,
}

impl CompileTimeData {
    /// parse file
    pub(crate) fn parse(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let raw: CompileTimeData = serde_json::from_str(&contents)?;
        Ok(raw)
    }

    /// Convert into Groth16VerifyCompressedRawInput.
    /// Runtime params are filled with empty values as their value doesn't dictate the
    /// configuration of binary circuit for which this function is used.
    pub(crate) fn into_compiletime_input(
        self,
    ) -> Groth16VerifyCompressedRawInput<INPUT_MESSAGE_LEN> {
        let raw_public_input: [u8; INPUT_MESSAGE_LEN] = [0; INPUT_MESSAGE_LEN];
        let proof_bytes: [u8; COMPRESSED_PROOF_SIZE] = [0; COMPRESSED_PROOF_SIZE];

        let mut vk: ark_groth16::VerifyingKey<ark_bn254::Bn254> =
            ark_groth16::VerifyingKey::deserialize_compressed_unchecked(&self.groth16_vk_bytes[..])
                .unwrap();

        // SP1 v6 has 5 public inputs with gamma_abc_g1 having 6 elements:
        // [0]: constant term (bias)
        // [1]: sp1_vkey_hash (compile-time constant)
        // [2]: committed_values_digest (runtime variable - kept)
        // [3]: exit_code (compile-time constant)
        // [4]: vk_root (compile-time constant)
        // [5]: proof_nonce (compile-time constant)
        //
        // Effect of raw public inputs known in compile time (e.g. SP1_VKEY_HASH) can be embedded into the circuit
        // through vk_y0 of groth16 verification key.
        // Given:
        // vk_y = (vk_y0, vk_y1, ..., vk_yn)
        // ks = (1, k1,...,kn)
        // For n scalars, you have n+1 verification key, with vk_y0 being something like a bias
        // if k1 is a hardcoded constant, obtain vk_y0' = vk_y0 + vk_y1 * k1.
        // Run msm with this vk_y0' and the rest of the n-1 variable scalars.
        // Since, vk_y0' will be a part of compile time constants, it will be embedded in binary circuit and as such be verifiable
        assert_eq!(
            vk.gamma_abc_g1.len(),
            6,
            "expected gamma_abc_g1 to contain 1 constant term plus 5 public input coefficients"
        );

        let sp1_vkey_hash: ark_bn254::Fr = self.sp1_vkey_hash.parse::<BigUint>().unwrap().into();
        let exit_code: ark_bn254::Fr = self.exit_code.parse::<BigUint>().unwrap().into();
        let vk_root: ark_bn254::Fr = self.vk_root.parse::<BigUint>().unwrap().into();
        let proof_nonce: ark_bn254::Fr = self.proof_nonce.parse::<BigUint>().unwrap().into();

        // Fold constant public inputs into gamma_abc_g1[0], keep committed_values_digest coefficient
        let committed_values_gamma = vk.gamma_abc_g1[2];
        let folded_gamma0 = vk.gamma_abc_g1[0]
            + vk.gamma_abc_g1[1] * sp1_vkey_hash
            + vk.gamma_abc_g1[3] * exit_code
            + vk.gamma_abc_g1[4] * vk_root
            + vk.gamma_abc_g1[5] * proof_nonce;

        // After folding, only committed_values_digest remains as the live public input
        vk.gamma_abc_g1 = vec![folded_gamma0.into_affine(), committed_values_gamma];

        let gnark_proof_bits: Vec<bool> = {
            let gnark_proof_bits: Vec<bool> = proof_bytes
                .iter()
                .flat_map(|&b| (0..8).map(move |i| ((b >> i) & 1) == 1))
                .collect();
            gnark_proof_bits
        };

        Groth16VerifyCompressedRawInput {
            public: InputMessage {
                byte_arr: raw_public_input,
            },
            proof: gnark_proof_bits.try_into().unwrap(),
            vk,
            proof_type: DEFAULT_PROOF_TYPE,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct RunTimeData {
    /// SP1 Groth16 Proof
    /// Proof in compressed gnark format
    groth16_proof: Vec<u8>,
    /// Public input committed by zkvm's host program
    /// It's called `raw` here because it is processed (hashed and converted to Fr)
    /// before feeding as an input to groth16 verifier
    raw_public_input: Vec<u8>,
}

impl RunTimeData {
    pub(crate) fn parse(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let raw: RunTimeData = serde_json::from_str(&contents)?;
        Ok(raw)
    }

    /// Convert into Groth16VerifyCompressedRawInput.
    /// Compile-time params are filled with empty values as their value doesn't dictate the
    /// representation or use of runtime data for which this function is used.
    pub(crate) fn into_runtime_input(self) -> Groth16VerifyCompressedRawInput<INPUT_MESSAGE_LEN> {
        let raw_public_input: [u8; INPUT_MESSAGE_LEN] = self.raw_public_input.try_into().unwrap();
        let proof_bytes: [u8; COMPRESSED_PROOF_SIZE] = self.groth16_proof.try_into().unwrap();
        let vk = ark_groth16::VerifyingKey::default();
        let gnark_proof_bits: Vec<bool> = {
            let gnark_proof_bits: Vec<bool> = proof_bytes
                .iter()
                .flat_map(|&b| (0..8).map(move |i| ((b >> i) & 1) == 1))
                .collect();
            gnark_proof_bits
        };
        Groth16VerifyCompressedRawInput {
            public: InputMessage {
                byte_arr: raw_public_input,
            },
            proof: gnark_proof_bits.try_into().unwrap(),
            vk,
            proof_type: DEFAULT_PROOF_TYPE,
        }
    }
}
