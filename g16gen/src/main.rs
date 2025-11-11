use g16ckt::{WireId, circuit::CircuitInput, gadgets::groth16::Groth16VerifyCompressedInput};
use tracing::info;

mod cache;
mod dummy_circuit;
mod modes;
mod passes;
mod proof_setup;
pub mod u24;

use cache::{save_cache, try_load_cache};
use passes::{
    credits::run_credits_pass, input_bits::write_input_bits, translation::run_translation_pass,
};
use proof_setup::generate_test_proof;

#[derive(Debug)]
enum Command {
    Generate { constraint_size: usize },
    WriteInputBits { constraint_size: usize },
    Help,
}

fn parse_args() -> Command {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        return Command::Generate { constraint_size: 6 };
    }

    match args[1].as_str() {
        "generate" => {
            let constraint_size = if args.len() > 2 {
                args[2].parse().unwrap_or(6)
            } else {
                6
            };
            Command::Generate { constraint_size }
        }
        "write-input-bits" => {
            let constraint_size = if args.len() > 2 {
                args[2].parse().unwrap_or(6)
            } else {
                6
            };
            Command::WriteInputBits { constraint_size }
        }
        "help" | "--help" | "-h" => Command::Help,
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            Command::Help
        }
    }
}

fn print_help() {
    println!("g16gen - Groth16 Boolean Circuit Generator");
    println!();
    println!("Generates boolean gate-level circuits encoding a Groth16 proof verifier.");
    println!();
    println!("USAGE:");
    println!("    g16gen <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    generate [k]           Generate boolean circuit file encoding Groth16 verifier");
    println!(
        "                           (default: k=6, creates verifier for 2^k constraint proofs)"
    );
    println!("    write-input-bits [k]   Extract boolean input bits for a specific Groth16 proof");
    println!("                           (default: k=6, outputs bits to input_bits.txt)");
    println!("    help                   Print this help message");
    println!();
    println!("EXAMPLES:");
    println!(
        "    g16gen generate 8             # Generate verifier circuit for 2^8 constraint proofs"
    );
    println!("    g16gen write-input-bits 6     # Extract input bits for a specific proof");
}

async fn run_generate(k: usize) {
    info!("Generating test proof with 2^{} constraints", k);
    let inputs = generate_test_proof(1 << k);

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Groth16VerifyCompressedInput::collect_wire_ids(&input_wires).len();
    println!("Primary input count: {}", primary_input_count);

    // Try to load credits and output wires from cache, or compute them
    let (credits, output_wires) = if let Some((credits, output_wires)) = try_load_cache() {
        info!("Loaded credits and output wires from cache");
        (credits, output_wires)
    } else {
        info!("Running credits pass...");
        let (credits, output_wires) = run_credits_pass(&inputs, primary_input_count);

        if let Err(e) = save_cache(&credits, &output_wires) {
            eprintln!("Warning: Failed to save cache: {}", e);
        } else {
            info!("Saved credits and output wires to cache");
        }

        (credits, output_wires)
    };

    // Run translation pass
    info!("Running translation pass...");
    run_translation_pass(&inputs, primary_input_count, credits, output_wires).await;
    info!("Circuit generation complete!");
}

async fn run_write_input_bits(k: usize) {
    info!("Generating test proof with 2^{} constraints", k);
    let inputs = generate_test_proof(1 << k);

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Groth16VerifyCompressedInput::collect_wire_ids(&input_wires).len();
    println!("Primary input count: {}", primary_input_count);

    info!("Writing input bits to file...");
    if let Err(e) = write_input_bits(&inputs) {
        eprintln!("Error writing input bits: {}", e);
        std::process::exit(1);
    }
    info!("Input bits written successfully!");
}

#[monoio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let command = parse_args();

    match command {
        Command::Generate { constraint_size } => {
            info!("Running generate command with k={}", constraint_size);
            run_generate(constraint_size).await;
        }
        Command::WriteInputBits { constraint_size } => {
            info!(
                "Running write-input-bits command with k={}",
                constraint_size
            );
            run_write_input_bits(constraint_size).await;
        }
        Command::Help => {
            print_help();
        }
    }
}
