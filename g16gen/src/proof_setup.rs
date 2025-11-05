use g16ckt::{
    Groth16VerifyInput,
    ark::{self, AffineRepr, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    gadgets::groth16::Groth16VerifyCompressedInput,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::dummy_circuit::DummyCircuit;

/// Generate a test proof and return compressed inputs for verification
pub fn generate_test_proof(num_constraints: usize) -> Groth16VerifyCompressedInput {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints,
    };

    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup failed");
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove failed");

    Groth16VerifyInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    }
    .compress()
}
