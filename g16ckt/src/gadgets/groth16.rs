//! Groth16 verifier gadget for BN254 using the streaming-circuit API.
//!
//! Implements the standard Groth16 verification equation with gadgets:
//! e(A, B) * e(C, -delta) * e(msm, -gamma) == e(alpha, beta)
//! where `msm = vk.gamma_abc_g1[0] + sum_i(public[i] * vk.gamma_abc_g1[i+1])`.

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use circuit_component_macro::component;
use num_bigint::BigUint;

use crate::{
    CircuitContext, WireId,
    circuit::{CircuitInput, CircuitMode, EncodeInput, TRUE_WIRE, WiresObject},
    gadgets::{
        bigint::{self, BigIntWires},
        bn254::{
            G2Projective, final_exponentiation::final_exponentiation_montgomery, fq::Fq,
            fq12::Fq12, fr::Fr, g1::G1Projective,
            pairing::multi_miller_loop_groth16_evaluate_montgomery_fast,
        },
    },
};

#[component]
pub fn projective_to_affine_montgomery<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
) -> G1Projective {
    let x = &p.x;
    let y = &p.y;
    let z = &p.z;

    let z_inverse = Fq::inverse_montgomery(circuit, z);
    let z_inverse_square = Fq::square_montgomery(circuit, &z_inverse);
    let z_inverse_cube = Fq::mul_montgomery(circuit, &z_inverse, &z_inverse_square);
    let new_x = Fq::mul_montgomery(circuit, x, &z_inverse_square);
    let new_y = Fq::mul_montgomery(circuit, y, &z_inverse_cube);

    G1Projective {
        x: new_x,
        y: new_y,
        // Set z = 1 in Montgomery form to stay in-domain
        z: Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).unwrap(),
    }
}

/// Verify Groth16 proof for BN254 using streaming gadgets.
///
/// - `public`: public inputs as Fr wires (bit-wires, Montgomery ops inside gadgets).
/// - `proof_a`, `proof_c`: proof G1 points as wires (Montgomery).
/// - `proof_b`: proof G2 point as host constant (affine).
/// - `vk`: verifying key with constant elements (host-provided arkworks types).
///
/// Returns a boolean wire that is 1 iff the proof verifies.
pub fn groth16_verify<C: CircuitContext>(
    circuit: &mut C,
    input: &Groth16VerifyInputWires,
) -> WireId {
    let Groth16VerifyInputWires {
        public,
        a,
        b,
        c,
        vk,
    } = input;

    let is_valid_field_and_group = {
        let is_valid_fr = {
            let mut and_all_wires = TRUE_WIRE;
            public.iter().for_each(|pubinp| {
                let r: BigUint = ark_bn254::Fr::MODULUS.into();
                let valid_pubinp = bigint::less_than_constant(circuit, pubinp, &r);
                let new_wire = circuit.issue_wire();
                circuit.add_gate(crate::Gate {
                    wire_a: and_all_wires,
                    wire_b: valid_pubinp,
                    wire_c: new_wire,
                    gate_type: crate::GateType::And,
                });
                and_all_wires = new_wire;
            });
            and_all_wires
        };

        // Verify that all group elements of input proof include valid base field elements
        let is_valid_fq = {
            let elems = [
                &a.x, &a.y, &a.z, &b.x.0[0], &b.x.0[1], &b.y.0[0], &b.y.0[1], &b.z.0[0], &b.z.0[1],
                &c.x, &c.y, &c.z,
            ];
            let mut and_all_wires = TRUE_WIRE;
            elems.iter().for_each(|pubinp| {
                let q: BigUint = ark_bn254::Fq::MODULUS.into();
                let valid_fq = bigint::less_than_constant(circuit, pubinp, &q);
                let new_wire = circuit.issue_wire();
                circuit.add_gate(crate::Gate {
                    wire_a: and_all_wires,
                    wire_b: valid_fq,
                    wire_c: new_wire,
                    gate_type: crate::GateType::And,
                });
                and_all_wires = new_wire;
            });
            and_all_wires
        };

        let is_on_curve = {
            let a_is_on_curve = G1Projective::is_on_curve(circuit, a);
            let b_is_on_curve = G2Projective::is_on_curve(circuit, b);
            let c_is_on_curve = G1Projective::is_on_curve(circuit, c);

            // valid group check
            let tmp0 = circuit.issue_wire();
            let is_on_curve = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: a_is_on_curve,
                wire_b: b_is_on_curve,
                wire_c: tmp0,
                gate_type: crate::GateType::And,
            });
            circuit.add_gate(crate::Gate {
                wire_a: tmp0,
                wire_b: c_is_on_curve,
                wire_c: is_on_curve,
                gate_type: crate::GateType::And,
            });
            is_on_curve
        };

        // valid fq and fr
        let is_valid_field = circuit.issue_wire();
        circuit.add_gate(crate::Gate {
            wire_a: is_valid_fr,
            wire_b: is_valid_fq,
            wire_c: is_valid_field,
            gate_type: crate::GateType::And,
        });

        // valid field and group check
        let is_valid_field_and_group = circuit.issue_wire();
        circuit.add_gate(crate::Gate {
            wire_a: is_valid_field,
            wire_b: is_on_curve,
            wire_c: is_valid_field_and_group,
            gate_type: crate::GateType::And,
        });
        is_valid_field_and_group
    };

    // Standard verification with public inputs
    // MSM: sum_i public[i] * gamma_abc_g1[i+1]
    let bases: Vec<ark_bn254::G1Projective> = vk
        .gamma_abc_g1
        .iter()
        .skip(1)
        .take(public.len())
        .map(|a| a.into_group())
        .collect();
    let msm_temp =
        G1Projective::msm_with_constant_bases_montgomery::<10, _>(circuit, public, &bases);

    // Add the constant term gamma_abc_g1[0] in Montgomery form
    let gamma0_m = G1Projective::as_montgomery(vk.gamma_abc_g1[0].into_group());
    let msm =
        G1Projective::add_montgomery(circuit, &msm_temp, &G1Projective::new_constant(&gamma0_m));

    let tmp_non_invertible_msm = bigint::equal_zero(circuit, &msm.z);
    let is_invertible_msm = circuit.issue_wire();
    circuit.add_gate(crate::Gate {
        wire_a: tmp_non_invertible_msm,
        wire_b: TRUE_WIRE,
        wire_c: is_invertible_msm,
        gate_type: crate::GateType::Xor,
    });

    let msm_affine = projective_to_affine_montgomery(circuit, &msm);

    let miller_result = multi_miller_loop_groth16_evaluate_montgomery_fast(
        circuit,
        &msm_affine,  // p1
        c,            // p2
        a,            // p3
        -vk.gamma_g2, // q1
        -vk.delta_g2, // q2
        b,            // q3
    );
    let is_valid_field_group_and_subgroup = circuit.issue_wire();
    circuit.add_gate(crate::Gate {
        wire_a: miller_result.is_valid,
        wire_b: is_valid_field_and_group,
        wire_c: is_valid_field_group_and_subgroup,
        gate_type: crate::GateType::And,
    });

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();

    let fin_exp = final_exponentiation_montgomery(circuit, &miller_result.f);
    let is_invertible = circuit.issue_wire();
    circuit.add_gate(crate::Gate {
        wire_a: fin_exp.is_valid,  // input to finexp was invertible
        wire_b: is_invertible_msm, // input to proj->affine was invertible
        wire_c: is_invertible,
        gate_type: crate::GateType::And,
    });

    let is_valid_proof =
        Fq12::equal_constant(circuit, &fin_exp.f, &Fq12::as_montgomery(alpha_beta));

    {
        // merge
        // #1: is valid field group and subgroup
        // #2: is_valid inversion
        // #3: is valid proof
        let tmp0 = circuit.issue_wire();
        circuit.add_gate(crate::Gate {
            wire_a: is_valid_field_group_and_subgroup,
            wire_b: is_invertible,
            wire_c: tmp0,
            gate_type: crate::GateType::And,
        });
        let all_valid = circuit.issue_wire();
        circuit.add_gate(crate::Gate {
            wire_a: tmp0,
            wire_b: is_valid_proof,
            wire_c: all_valid,
            gate_type: crate::GateType::And,
        });
        all_valid
    }
}

/// Verify a 128-byte compressed serialized groth16 proof using public inputs
pub fn groth16_verify_compressed<C: CircuitContext>(
    circuit: &mut C,
    input: &Groth16VerifyCompressedInputWires,
) -> crate::WireId {
    let proof = input.proof.deserialize_checked(circuit);

    let verified_res = groth16_verify(
        circuit,
        &Groth16VerifyInputWires {
            public: input.public.clone(),
            a: proof.a,
            b: proof.b,
            c: proof.c,
            vk: input.vk.clone(),
        },
    );

    let valid = circuit.issue_wire();
    circuit.add_gate(crate::Gate {
        wire_a: verified_res, // proof verification was successful
        wire_b: proof.valid,  // input is valid
        wire_c: valid,
        gate_type: crate::GateType::And,
    });
    valid
}

#[derive(Debug, Clone)]
pub struct Groth16VerifyInput {
    pub public: Vec<ark_bn254::Fr>,
    pub a: ark_bn254::G1Projective,
    pub b: ark_bn254::G2Projective,
    pub c: ark_bn254::G1Projective,
    pub vk: VerifyingKey<Bn254>,
}

#[derive(Debug)]
pub struct Groth16VerifyInputWires {
    pub public: Vec<Fr>,
    pub a: G1Projective,
    pub b: G2Projective,
    pub c: G1Projective,
    pub vk: VerifyingKey<Bn254>,
}

impl CircuitInput for Groth16VerifyInput {
    type WireRepr = Groth16VerifyInputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16VerifyInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            a: G1Projective::new(&mut issue),
            b: G2Projective::new(&mut issue),
            c: G1Projective::new(issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Groth16VerifyInput {
    fn encode(&self, repr: &Groth16VerifyInputWires, cache: &mut M) {
        // Encode public scalars
        for (w, v) in repr.public.iter().zip(self.public.iter()) {
            let fr_fn = Fr::get_wire_bits_fn(w, v).unwrap();

            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Encode G1 points (Montgomery coordinates)
        let a_m = G1Projective::as_montgomery(self.a);
        let b_m = G2Projective::as_montgomery(self.b);
        let c_m = G1Projective::as_montgomery(self.c);

        let a_fn = G1Projective::get_wire_bits_fn(&repr.a, &a_m).unwrap();
        for &wire_id in repr
            .a
            .x
            .iter()
            .chain(repr.a.y.iter())
            .chain(repr.a.z.iter())
        {
            if let Some(bit) = a_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }

        let b_fn = G2Projective::get_wire_bits_fn(&repr.b, &b_m).unwrap();
        for &wire_id in repr
            .b
            .x
            .iter()
            .chain(repr.b.y.iter())
            .chain(repr.b.z.iter())
        {
            if let Some(bit) = b_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }

        let c_fn = G1Projective::get_wire_bits_fn(&repr.c, &c_m).unwrap();
        for &wire_id in repr
            .c
            .x
            .iter()
            .chain(repr.c.y.iter())
            .chain(repr.c.z.iter())
        {
            if let Some(bit) = c_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
    }
}

impl Groth16VerifyInput {
    pub fn compress(self) -> Groth16VerifyCompressedInput {
        let public = self.public.into_iter().map(|x| x.into()).collect();
        let mut proof_bytes = Vec::new();
        ark_groth16::Proof::<Bn254> {
            a: self.a.into(),
            b: self.b.into(),
            c: self.c.into(),
        }
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");
        let proof_bits: Vec<bool> = proof_bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| ((b >> i) & 1) == 1))
            .collect();
        Groth16VerifyCompressedInput {
            public,
            proof: proof_bits.try_into().unwrap(),
            vk: self.vk,
        }
    }
}

type SerializedCompressedProof = [bool; 128 * 8];
/// Compressed representation of groth16 proof
pub struct Groth16VerifyCompressedInput {
    pub public: Vec<BigUint>,
    pub proof: SerializedCompressedProof, // 128 byte proof
    pub vk: VerifyingKey<Bn254>,
}

/// Compressed groth16 proof with public inputs
#[derive(Debug)]
pub struct Groth16VerifyCompressedInputWires {
    pub public: Vec<Fr>,
    pub proof: SerializedCompressedProofWires,
    pub vk: VerifyingKey<Bn254>,
}

/// Serialized 128 byte representation of groth16 proof in arkworks' serialized format
#[derive(Debug, Clone, Copy)]
pub struct SerializedCompressedProofWires(pub [WireId; 128 * 8]);

/// Groth16 Proof elements `{a, b, c}` along with `valid` flag indicating whether the
/// input (i.e. `SerializedCompressedProofWires`), from which this was obtained, was valid to begin with.
#[derive(Debug, Clone)]
pub struct DeserializedCompressedProofWires {
    a: G1Projective,
    b: G2Projective,
    c: G1Projective,
    valid: WireId,
}

impl SerializedCompressedProofWires {
    pub fn new(issue: &mut impl FnMut() -> WireId) -> Self {
        let v: Vec<WireId> = std::iter::repeat_with(issue).take(128 * 8).collect();
        let v: [WireId; 128 * 8] = v.try_into().unwrap();
        Self(v)
    }
    pub fn deserialize_checked<C: CircuitContext>(
        &self,
        circuit: &mut C,
    ) -> DeserializedCompressedProofWires {
        let compressed_a: [WireId; 32 * 8] = self.0[0..32 * 8].try_into().unwrap();
        let compressed_b: [WireId; 64 * 8] = self.0[32 * 8..96 * 8].try_into().unwrap();
        let compressed_c: [WireId; 32 * 8] = self.0[96 * 8..].try_into().unwrap();

        let a_decomp = G1Projective::deserialize_checked(circuit, compressed_a);
        let b_decomp = G2Projective::deserialize_checked(circuit, compressed_b);
        let c_decomp = G1Projective::deserialize_checked(circuit, compressed_c);

        let ab_valid = circuit.issue_wire();
        let abc_valid = circuit.issue_wire();

        circuit.add_gate(crate::Gate {
            wire_a: a_decomp.is_valid,
            wire_b: b_decomp.is_valid,
            wire_c: ab_valid,
            gate_type: crate::GateType::And,
        });
        circuit.add_gate(crate::Gate {
            wire_a: ab_valid,
            wire_b: c_decomp.is_valid,
            wire_c: abc_valid,
            gate_type: crate::GateType::And,
        });

        DeserializedCompressedProofWires {
            a: a_decomp.point,
            b: b_decomp.point,
            c: c_decomp.point,
            valid: abc_valid,
        }
    }
}

impl WiresObject for SerializedCompressedProofWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.to_vec()
    }
    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        SerializedCompressedProofWires::new(wire_gen)
    }
}

impl WiresObject for Groth16VerifyCompressedInputWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        Groth16VerifyCompressedInput::collect_wire_ids(self)
    }

    fn clone_from(&self, mut issue: &mut impl FnMut() -> WireId) -> Self {
        Groth16VerifyCompressedInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            proof: self.proof.clone_from(issue),
            vk: self.vk.clone(),
        }
    }
}

impl CircuitInput for Groth16VerifyCompressedInput {
    type WireRepr = Groth16VerifyCompressedInputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16VerifyCompressedInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            proof: SerializedCompressedProofWires::new(&mut issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.proof.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Groth16VerifyCompressedInput {
    fn encode(&self, repr: &Groth16VerifyCompressedInputWires, cache: &mut M) {
        // Encode public scalars
        for (w, v) in repr.public.iter().zip(self.public.iter()) {
            let fr_fn = BigIntWires::get_wire_bits_fn(w, v).unwrap();

            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        self.proof.iter().zip(repr.proof.0).for_each(|(x, y)| {
            cache.feed_wire(y, *x);
        });
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, short_weierstrass::SWCurveConfig};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use test_log::test;

    use super::*;
    use crate::{
        Fq2Wire,
        circuit::{CircuitBuilder, StreamingResult},
    };

    // Helper to reduce duplication across bitflip tests for A, B, and C
    fn run_false_bitflip_test(seed: u64, mutate: impl FnOnce(&mut Groth16VerifyInput)) {
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Apply caller-provided mutation to corrupt a component
        mutate(&mut inputs);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(!out.output_value);
    }

    #[derive(Copy, Clone)]
    struct DummyCircuit<F: ark_ff::PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;
            Ok(())
        }
    }

    // Circuit with no public inputs - only private witnesses
    #[derive(Copy, Clone)]
    struct DummyCircuitNoPublicInputs<F: ark_ff::PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuitNoPublicInputs<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_witness_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;
            Ok(())
        }
    }

    #[test]
    fn test_groth16_verify_true() {
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Build inputs for gadget (convert A,C to projective for wire encoding)
        let inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 40_000, groth16_verify);

        assert!(out.output_value);
    }

    #[test]
    fn test_groth16_verify_false_bitflip_a() {
        run_false_bitflip_test(54321, |inputs| {
            inputs.a.x += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_false_bitflip_b() {
        run_false_bitflip_test(98765, |inputs| {
            // Flip one limb by adding ONE to c0 of x
            inputs.b.x.c0 += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_false_bitflip_c() {
        run_false_bitflip_test(19283, |inputs| {
            inputs.c.x += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_true() {
        // Test successful verification with empty public inputs
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(99999);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            out.output_value,
            "Valid proof with empty public inputs should verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_a() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.a
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(88888);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.a by using a different random point
        inputs.a = ark_bn254::G1Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_b() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.b
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(77777);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.b by using a different random point
        inputs.b = ark_bn254::G2Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_c() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.c
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(66666);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.c by using a different random point
        inputs.c = ark_bn254::G1Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_false_random() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        // Create a valid vk from a small circuit
        let k = 4;
        let mut rng = ChaCha20Rng::seed_from_u64(777);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (_pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        // Random, unrelated inputs instead of a valid proof
        let inputs = Groth16VerifyInput {
            public: vec![ark_bn254::Fr::rand(&mut rng)],
            a: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            b: (ark_bn254::G2Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            c: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            vk,
        };

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(!out.output_value);
    }

    #[test]
    fn test_cofactor_clearing() {
        let mut rng = ChaCha20Rng::seed_from_u64(112);
        for _ in 0..5 {
            // sufficient sample size to sample both valid and invalid points
            let x = ark_bn254::Fq2::rand(&mut rng);
            let a1 = ark_bn254::Fq2::sqrt(&((x * x * x) + ark_bn254::g2::Config::COEFF_B));
            let (y, ref_is_valid) = if let Some(a1) = a1 {
                // if it is possible to take square root, you have found correct y,
                (a1, true)
            } else {
                // else generate some random value
                (ark_bn254::Fq2::rand(&mut rng), false)
            };
            let pt = ark_bn254::G2Affine::new_unchecked(x, y);

            let pt = pt.into_group();
            const COFACTOR: &[u64] = &[
                0x345f2299c0f9fa8d,
                0x06ceecda572a2489,
                0xb85045b68181585e,
                0x30644e72e131a029,
            ];
            let pt = pt.mul_bigint(COFACTOR);
            let pt = pt.into_affine();
            // if it's a valid point, it should be on curve and subgroup (after cofactor clearing)
            assert_eq!(
                ref_is_valid,
                pt.is_on_curve() && pt.is_in_correct_subgroup_assuming_on_curve()
            );
        }
    }

    #[test]
    fn test_groth16_compressed_decompress_matches_proof_points() {
        let k = 4; // keep it small
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyInput {
            public: vec![ark_bn254::Fr::from(0u64)], // unused here
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        }
        .compress();

        let out: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 80_000, |ctx, wires| {
                let proof_dec = wires.proof.deserialize_checked(ctx);

                let a_dec = proof_dec.a;
                let b_dec = proof_dec.b;
                let c_dec = proof_dec.c;

                let a_exp = G1Projective::as_montgomery(proof.a.into_group());
                let b_exp = G2Projective::as_montgomery(proof.b.into_group());
                let c_exp = G1Projective::as_montgomery(proof.c.into_group());

                let a_x_ok = Fq::equal_constant(ctx, &a_dec.x, &a_exp.x);
                let a_y_ok = Fq::equal_constant(ctx, &a_dec.y, &a_exp.y);
                let a_z_ok = Fq::equal_constant(ctx, &a_dec.z, &a_exp.z);

                let b_x_ok = Fq2Wire::equal_constant(ctx, &b_dec.x, &b_exp.x);
                let b_y_ok = Fq2Wire::equal_constant(ctx, &b_dec.y, &b_exp.y);
                let b_z_ok = Fq2Wire::equal_constant(ctx, &b_dec.z, &b_exp.z);

                let c_x_ok = Fq::equal_constant(ctx, &c_dec.x, &c_exp.x);
                let c_y_ok = Fq::equal_constant(ctx, &c_dec.y, &c_exp.y);
                let c_z_ok = Fq::equal_constant(ctx, &c_dec.z, &c_exp.z);

                vec![
                    a_x_ok,
                    a_y_ok,
                    a_z_ok,
                    b_x_ok,
                    b_y_ok,
                    b_z_ok,
                    c_x_ok,
                    c_y_ok,
                    c_z_ok,
                    proof_dec.valid,
                ]
            });

        assert!(out.output_value.iter().all(|&b| b));
    }

    #[test]
    fn test_invalid_groth16_verify_compressed_true_small() {
        // get valid point in curve that is not in subgroup
        fn random_g2_affine_sg(rng: &mut impl Rng) -> ark_bn254::G2Affine {
            let mut pt = ark_bn254::G2Affine::identity();
            for _ in 0..5 {
                // sufficient sample size to sample both valid and invalid points
                let x = ark_bn254::Fq2::rand(rng);
                let a1 = ark_bn254::Fq2::sqrt(&((x * x * x) + ark_bn254::g2::Config::COEFF_B));
                let (y, ref_is_valid) = if let Some(a1) = a1 {
                    // if it is possible to take square root, you have found correct y,
                    (a1, true)
                } else {
                    // else generate some random value
                    (ark_bn254::Fq2::rand(rng), false)
                };
                if ref_is_valid {
                    pt = ark_bn254::G2Affine::new_unchecked(x, y);
                    break;
                }
            }
            pt
        }

        let k = 4; // circuit size; pairing cost dominates anyway
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Case 1: Check that the proof is correct to begin with
        let inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk: vk.clone(),
        }
        .compress();

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 160_000, groth16_verify_compressed);

        assert!(out.output_value, "should pass");

        // Case 2: Check for invalid proof
        let inputs = Groth16VerifyInput {
            public: vec![c_val],

            a: proof.a.into_group(),
            b: random_g2_affine_sg(&mut rng).into_group(), // proof.b.into_group()
            c: proof.c.into_group(),
            vk,
        }
        .compress();

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 160_000, groth16_verify_compressed);

        assert!(!out.output_value, "should fail because invalid G2");
    }

    // Full end-to-end compressed Groth16 verification. This is heavy because it
    // runs Miller loop + final exponentiation in-circuit. Kept for completeness
    // but ignored by default; run explicitly when needed.
    #[test]
    fn test_groth16_verify_compressed_true_small() {
        let k = 4; // circuit size; pairing cost dominates anyway
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        }
        .compress();

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 80_000, groth16_verify_compressed);

        assert!(out.output_value);
    }

    // Unified small verifier runner to avoid duplication across flows and bitflips
    #[derive(Copy, Clone)]
    enum VerifyFlow {
        Uncompressed,
        Compressed,
    }

    fn run_small_verify(
        flow: VerifyFlow,
        seed: u64,
        mutate: impl FnOnce(&mut Groth16VerifyInput),
    ) -> bool {
        let k = 4; // small circuit to keep test fast
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };
        mutate(&mut inputs);

        match flow {
            VerifyFlow::Uncompressed => {
                let out: StreamingResult<_, _, bool> =
                    CircuitBuilder::streaming_execute(inputs, 40_000, groth16_verify);

                out.output_value
            }
            VerifyFlow::Compressed => {
                let out: StreamingResult<_, _, bool> = CircuitBuilder::streaming_execute(
                    inputs.compress(),
                    80_000,
                    groth16_verify_compressed,
                );

                out.output_value
            }
        }
    }

    // Unified small verifier tests across flows
    #[test]
    fn test_small_verify_true_uncompressed() {
        assert!(run_small_verify(VerifyFlow::Uncompressed, 10101, |_| {}));
    }
    #[test]
    fn test_small_verify_true_compressed() {
        assert!(run_small_verify(VerifyFlow::Compressed, 20202, |_| {}));
    }
    #[test]
    fn test_small_verify_false_bitflip_a_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            30303,
            |inputs| {
                inputs.a.x += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_a_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 40404, |inputs| {
            inputs.a.x += ark_bn254::Fq::ONE;
        }));
    }
    #[test]
    fn test_small_verify_false_bitflip_b_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            50505,
            |inputs| {
                inputs.b.x.c0 += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_b_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 60606, |inputs| {
            inputs.b.x.c0 += ark_bn254::Fq::ONE;
        }));
    }
    #[test]
    fn test_small_verify_false_bitflip_c_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            70707,
            |inputs| {
                inputs.c.x += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_c_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 80808, |inputs| {
            inputs.c.x += ark_bn254::Fq::ONE;
        }));
    }

    #[test]
    fn test_ark_proof_decompress_matches() {
        let ark_proof_bytes: [u8; 128] = [
            55, 126, 31, 52, 68, 72, 45, 185, 179, 42, 69, 122, 227, 134, 234, 167, 80, 68, 65,
            142, 134, 133, 97, 24, 194, 180, 193, 213, 111, 19, 12, 42, 142, 193, 123, 63, 163, 6,
            122, 100, 126, 178, 41, 127, 97, 82, 169, 2, 30, 190, 130, 153, 110, 203, 2, 95, 89,
            162, 70, 74, 63, 232, 176, 42, 39, 119, 13, 172, 154, 135, 98, 126, 217, 67, 36, 222,
            136, 93, 161, 93, 1, 196, 101, 172, 163, 240, 105, 124, 107, 93, 222, 133, 118, 94,
            161, 14, 165, 232, 61, 136, 121, 145, 0, 171, 184, 234, 57, 160, 1, 248, 7, 195, 124,
            95, 50, 113, 24, 203, 211, 73, 196, 40, 173, 148, 179, 126, 12, 131,
        ];
        let ark_proof = ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed_unchecked(
            &ark_proof_bytes[..],
        )
        .unwrap();
        let ark_proof_bits: Vec<bool> = ark_proof_bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| ((b >> i) & 1) == 1))
            .collect();

        let inputs = Groth16VerifyCompressedInput {
            public: vec![],
            proof: ark_proof_bits.try_into().unwrap(),
            vk: ark_groth16::VerifyingKey::default(),
        };

        let result: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 80_000, |ctx, wires| {
                let result_wires = wires.proof.deserialize_checked(ctx).b;
                let mut output_ids = Vec::new();
                output_ids.extend(result_wires.x.iter());
                output_ids.extend(result_wires.y.iter());
                output_ids.extend(result_wires.z.iter());
                output_ids
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());

        let ark_proof_a_mont = G2Projective::as_montgomery(ark_proof.b.into());
        assert_eq!(actual_result, ark_proof_a_mont);
    }
}
