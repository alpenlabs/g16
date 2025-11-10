use crate::modes::fanout_ctr::FanoutCounter;

use g16ckt::{
    WireId,
    circuit::{StreamingMode, component_meta::ComponentMetaBuilder},
    gadgets::groth16::Groth16VerifyCompressedInput,
    groth16_verify_compressed,
};
use std::time::Instant;
use tracing::info;

/// Run the credits pass to compute wire credits
pub fn run_credits_pass(
    inputs: &Groth16VerifyCompressedInput,
    primary_input_count: usize,
) -> (Vec<u16>, Vec<WireId>) {
    let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(inputs);
    let mut metadata_mode = StreamingMode::<FanoutCounter>::MetadataPass(root_meta);

    let metadata_start = Instant::now();
    // Run circuit construction in metadata mode
    let meta_output_wires = {
        let ok = groth16_verify_compressed(&mut metadata_mode, &allocated_inputs);
        vec![ok]
    };
    let metadata_time = metadata_start.elapsed();
    println!("Credits metadata time: {:?}", metadata_time);

    // Convert to execution mode
    let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
        FanoutCounter::new(primary_input_count),
        inputs,
        &meta_output_wires.iter().map(|&w| w).collect::<Vec<_>>(),
    );

    let credits_start = Instant::now();
    // Run the credits pass
    let real_output_wires = {
        let ok = groth16_verify_compressed(&mut ctx, &allocated_inputs);
        vec![ok]
    };
    println!("Output wires: {:?}", real_output_wires);

    let (mut fanout, biggest_credits_seen) = ctx.get_mut_mode().unwrap().finish();
    println!("Biggest credits seen: {}", biggest_credits_seen);
    let elapsed_credits = credits_start.elapsed();
    info!(
        "Completed credits pass ({} wires) in {:?}",
        fanout.len(),
        elapsed_credits
    );

    // Set credits for output wires to 0
    for output_wire in &real_output_wires {
        fanout[output_wire.0] = 0;
    }

    (fanout, real_output_wires)
}
