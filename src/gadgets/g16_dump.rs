// Credits analysis example - tracks REAL credits from actual circuit execution
// Run with: `cargo run --example credits_analysis --release`

use crate::{
    FrWire, G1Wire, G2Wire, Gate, Groth16VerifyInputWires, WireId,
    ark::{self, AffineRepr, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{
        CircuitInput, CircuitMode, EncodeInput, WiresObject,
        modes::{CreditCollectionMode, ExecuteMode, TranslationMode},
    },
    groth16_verify,
    storage::Credits,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{
    collections::HashMap,
    io::{BufReader, BufWriter, Read, Write},
    time::Instant,
};
use std::{
    fs::{File, OpenOptions},
    num::NonZero,
};
use tracing::info;

// Circuit for generating proofs
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

// Input structure for Groth16 verifier
struct Inputs {
    public: Vec<ark::Fr>,
    a: ark::G1Projective,
    b: ark::G2Projective,
    c: ark::G1Projective,
}

struct InputWires {
    public: Vec<FrWire>,
    a: G1Wire,
    b: G2Wire,
    c: G1Wire,
}

impl CircuitInput for Inputs {
    type WireRepr = InputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        InputWires {
            public: self
                .public
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: G1Wire::new(&mut issue),
            b: G2Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
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

impl EncodeInput<CreditCollectionMode> for Inputs {
    fn encode(&self, _repr: &InputWires, _cache: &mut CreditCollectionMode) {}
}

impl EncodeInput<TranslationMode> for Inputs {
    fn encode(&self, _repr: &InputWires, _cache: &mut TranslationMode) {}
}

fn run(k: usize) {
    // Build circuit and proof
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    let inputs = Inputs {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
    };

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Inputs::collect_wire_ids(&input_wires).len();

    const CREDITS_FILE: &str = "credits.cache";

    let credits = if let Ok(credits_file) = OpenOptions::new().read(true).open(CREDITS_FILE) {
        let mut credits: Vec<u16> = Vec::new();
        let mut reader = BufReader::new(credits_file);
        loop {
            let mut buf = [0u8; 2];
            if reader.read_exact(&mut buf).is_err() {
                break;
            }
            credits.push(u16::from_le_bytes(buf));
        }
        credits
    } else {
        let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(&inputs);
        let mut metadata_mode = StreamingMode::<CreditCollectionMode>::MetadataPass(root_meta);

        let metadata_start = Instant::now();
        // Run circuit construction in metadata mode
        let root_output = {
            let ok = groth16_verify(
                &mut metadata_mode,
                &Groth16VerifyInputWires {
                    public: allocated_inputs.public,
                    a: allocated_inputs.a,
                    b: allocated_inputs.b,
                    c: allocated_inputs.c,
                    vk: vk.clone(),
                },
            );
            vec![ok]
        };
        let metadata_time = metadata_start.elapsed();
        println!("metadata time: {:?}", metadata_time);

        let output_wires = root_output.iter().map(|&w| w).collect::<Vec<_>>();

        // Convert to execution mode with our logging wrapper
        let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
            CreditCollectionMode::new(primary_input_count),
            &inputs,
            &output_wires,
        );

        let credits_start = Instant::now();
        // Run the credits pass
        let _ = {
            let ok = groth16_verify(
                &mut ctx,
                &Groth16VerifyInputWires {
                    public: allocated_inputs.public,
                    a: allocated_inputs.a,
                    b: allocated_inputs.b,
                    c: allocated_inputs.c,
                    vk: vk.clone(),
                },
            );
            vec![ok]
        };

        let credits = ctx.get_mut_mode().unwrap().finish();
        let elapsed_credits = credits_start.elapsed();
        info!(
            "completed credits pass ({}) in {:?}",
            credits.len(),
            elapsed_credits
        );

        // save credits to file
        if let Ok(credits_file) = OpenOptions::new()
            .write(true)
            .create(true)
            .open(CREDITS_FILE)
        {
            let mut writer = BufWriter::new(credits_file);
            for credit in &credits {
                writer.write_all(&credit.to_le_bytes()).unwrap();
            }
            writer.flush().unwrap();
        }

        credits
    };

    // Create custom builder that can access the mode
    use crate::circuit::{StreamingMode, component_meta::ComponentMetaBuilder};

    ////////////////// translation pass

    let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(&inputs);
    let mut metadata_mode = StreamingMode::<TranslationMode>::MetadataPass(root_meta);

    let metadata_start = Instant::now();
    // Run circuit construction in metadata mode
    let root_output = {
        let ok = groth16_verify(
            &mut metadata_mode,
            &Groth16VerifyInputWires {
                public: allocated_inputs.public,
                a: allocated_inputs.a,
                b: allocated_inputs.b,
                c: allocated_inputs.c,
                vk: vk.clone(),
            },
        );
        vec![ok]
    };
    let metadata_time = metadata_start.elapsed();
    println!("metadata time: {:?}", metadata_time);

    let output_wires = root_output.iter().map(|&w| w).collect::<Vec<_>>();

    const OUTPUT_FILE: &str = "g16.ckt";

    let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
        TranslationMode::new(
            primary_input_count,
            credits,
            OUTPUT_FILE,
            primary_input_count as u64,
            output_wires.iter().map(|w| w.0 as u64).collect(),
        ),
        &inputs,
        &output_wires,
    );

    let translation_start = Instant::now();
    // Run the translation pass
    let result = {
        let ok = groth16_verify(
            &mut ctx,
            &Groth16VerifyInputWires {
                public: allocated_inputs.public.clone(),
                a: allocated_inputs.a,
                b: allocated_inputs.b,
                c: allocated_inputs.c,
                vk: vk.clone(),
            },
        );
        vec![ok]
    };

    let elapsed_translation = translation_start.elapsed();
    info!(
        "completed translation pass ({}) in {:?}",
        allocated_inputs.public.len(),
        elapsed_translation
    );
    ctx.get_mut_mode().unwrap().finish();
}

fn main() {
    tracing_subscriber::fmt::init();

    let test_sizes = vec![6];

    for k in test_sizes {
        run(k);
    }
}
