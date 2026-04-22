use std::path::PathBuf;

use g16ckt::{WireId, circuit::CircuitInput, gadgets::groth16::Groth16VerifyCompressedRawInput};
use tracing::info;

mod cache;
mod circuit_args;
mod modes;
mod passes;

use cache::{save_cache, try_load_cache};
use passes::{
    credits::run_credits_pass, input_bits::write_input_bits, translation::run_translation_pass,
};

use crate::circuit_args::{CompileTimeData, RunTimeData};

#[derive(Debug)]
enum Command {
    Generate { conf: PathBuf },
    WriteInputBits { conf: PathBuf },
    Help,
}

fn parse_args() -> Command {
    let mut args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Expected total of two arguments in the form g16gen <COMMAND> [OPTIONS]");
        args = vec![String::from("help")];
    }

    match args[1].as_str() {
        "generate" => {
            let path_to_conf = PathBuf::from(args[2].trim());
            Command::Generate { conf: path_to_conf }
        }
        "write-input-bits" => {
            let path_to_conf = PathBuf::from(args[2].trim());
            Command::WriteInputBits { conf: path_to_conf }
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
    println!(
        "    generate path_to_compile_time_config           Generate boolean circuit file encoding Groth16 verifier"
    );
    println!(
        "    write-input-bits path_to_run_time_config       Extract boolean input bits for a specific Groth16 proof"
    );
    println!("                           (outputs bits to inputs.txt)");
    println!("    help                   Print this help message");
    println!();
    println!("EXAMPLES:");
    println!(
        "    g16gen generate example_config/compile_time.json             # Generate verifier circuit sp1 groth16 verifier"
    );
    println!(
        "    g16gen write-input-bits example_config/run_time.json     # Extract input bits for a specific proof"
    );
}

async fn run_generate(conf: PathBuf) {
    let parsed_data = CompileTimeData::parse(conf).expect("expect data is parsed");
    let inputs = parsed_data.into_compiletime_input();

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Groth16VerifyCompressedRawInput::collect_wire_ids(&input_wires).len();
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

async fn run_write_input_bits(conf: PathBuf) {
    let parsed_data = RunTimeData::parse(conf).expect("expect data is parsed");
    let inputs = parsed_data.into_runtime_input();

    let input_wires = inputs.allocate(|| WireId(0)); // Dummy wire generator
    let primary_input_count = Groth16VerifyCompressedRawInput::collect_wire_ids(&input_wires).len();
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
        Command::Generate { conf } => {
            info!("Running generate command with config on path {:?}", conf);
            run_generate(conf).await;
        }
        Command::WriteInputBits { conf } => {
            info!("Running write-input-bits command config on path {:?}", conf);
            run_write_input_bits(conf).await;
        }
        Command::Help => {
            print_help();
        }
    }
}
