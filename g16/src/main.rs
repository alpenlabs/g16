use std::{
    fs::OpenOptions,
    io::{BufReader, BufWriter, Read, Write},
    time::Instant,
};

use g16ckt::{
    Groth16VerifyInput, WireId,
    ark::{self, AffineRepr, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitInput, StreamingMode, component_meta::ComponentMetaBuilder},
    gadgets::groth16::Groth16VerifyCompressedInput,
    groth16_verify_compressed,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing::info;

use crate::{
    modes::{credit::CreditCollectionMode, translate::TranslationMode},
    u24::U24,
};

mod modes;
pub mod u24;

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

async fn run(k: usize) {
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

    let inputs = Groth16VerifyInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    }
    .compress();

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Groth16VerifyCompressedInput::collect_wire_ids(&input_wires).len();
    println!("Primary input count: {}", primary_input_count);

    const CREDITS_FILE: &str = "credits.cache";
    const OUTPUT_WIRES_FILE: &str = "outputs.cache";

    let (credits, output_wires) = if let Ok(credits_file) =
        OpenOptions::new().read(true).open(CREDITS_FILE)
        && let Ok(output_wires_file) = OpenOptions::new().read(true).open(OUTPUT_WIRES_FILE)
    {
        let mut credits: Vec<U24> = Vec::new();
        let mut reader = BufReader::new(credits_file);
        loop {
            let mut buf = [0u8; 3];
            if reader.read_exact(&mut buf).is_err() {
                break;
            }
            credits.push(U24::new(buf));
        }

        let mut output_wires = Vec::new();
        let mut reader = BufReader::new(output_wires_file);
        loop {
            let mut buf = [0u8; 8];
            if reader.read_exact(&mut buf).is_err() {
                break;
            }
            output_wires.push(WireId(usize::from_le_bytes(buf)));
        }

        (credits, output_wires)
    } else {
        let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(&inputs);
        let mut metadata_mode = StreamingMode::<CreditCollectionMode>::MetadataPass(root_meta);

        let metadata_start = Instant::now();
        // Run circuit construction in metadata mode
        let meta_output_wires = {
            let ok = groth16_verify_compressed(&mut metadata_mode, &allocated_inputs);
            vec![ok]
        };
        let metadata_time = metadata_start.elapsed();
        println!("metadata time: {:?}", metadata_time);

        // Convert to execution mode with our logging wrapper
        let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
            CreditCollectionMode::new(primary_input_count),
            &inputs,
            &meta_output_wires.to_vec(),
        );

        let credits_start = Instant::now();
        // Run the credits pass
        let real_output_wires = {
            let ok = groth16_verify_compressed(&mut ctx, &allocated_inputs);
            vec![ok]
        };
        println!("output wires: {:?}", real_output_wires);

        let (mut credits, biggest_credits_seen) = ctx.get_mut_mode().unwrap().finish();
        println!("biggest credits seen: {}", biggest_credits_seen);
        let elapsed_credits = credits_start.elapsed();
        info!(
            "completed credits pass ({}) in {:?}",
            credits.len(),
            elapsed_credits
        );

        // set credits for output wires to 0
        for output_wire in &real_output_wires {
            credits[output_wire.0] = 0u32.into();
        }

        // save credits to file
        if let Ok(credits_file) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(CREDITS_FILE)
        {
            let mut writer = BufWriter::new(credits_file);
            for credit in &credits {
                writer.write_all(&credit.to_bytes()).unwrap();
            }
            writer.flush().unwrap();
        }

        // save outputs to file
        if let Ok(output_wires_file) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(OUTPUT_WIRES_FILE)
        {
            let mut writer = BufWriter::new(output_wires_file);
            for output_wire in &real_output_wires {
                writer.write_all(&output_wire.0.to_le_bytes()).unwrap();
            }
            writer.flush().unwrap();
        }

        (credits, real_output_wires)
    };

    ////////////////// translation pass

    let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(&inputs);
    let mut metadata_mode = StreamingMode::<TranslationMode>::MetadataPass(root_meta);

    let metadata_start = Instant::now();
    // Run circuit construction in metadata mode
    let meta_output_wires = {
        let ok = groth16_verify_compressed(&mut metadata_mode, &allocated_inputs);
        vec![ok]
    };
    let metadata_time = metadata_start.elapsed();
    println!("metadata time: {:?}", metadata_time);

    let meta_output_wires = meta_output_wires.to_vec();

    const OUTPUT_FILE: &str = "g16.ckt";

    let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
        TranslationMode::new(
            primary_input_count,
            credits,
            OUTPUT_FILE,
            primary_input_count as u64,
            output_wires.clone(),
        )
        .await,
        &inputs,
        &meta_output_wires,
    );

    let translation_start = Instant::now();
    // Run the translation pass
    let translation_output_wires = {
        let ok = groth16_verify_compressed(&mut ctx, &allocated_inputs);
        vec![ok]
    };

    assert_eq!(translation_output_wires, output_wires);

    let elapsed_translation = translation_start.elapsed();
    info!(
        "completed translation pass ({}) in {:?}",
        allocated_inputs.public.len(),
        elapsed_translation
    );
    ctx.get_mut_mode().unwrap().finish();
}

#[monoio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let test_sizes = vec![6];

    for k in test_sizes {
        run(k).await;
    }
}
