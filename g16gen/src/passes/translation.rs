use crate::modes::translate::TranslationMode;
use crate::u24::U24;
use g16ckt::{
    WireId,
    circuit::{StreamingMode, component_meta::ComponentMetaBuilder},
    gadgets::groth16::Groth16VerifyCompressedInput,
    groth16_verify_compressed,
};
use std::time::Instant;
use tracing::info;

const OUTPUT_FILE: &str = "g16.ckt";

/// Run the translation pass to generate the circuit file
pub async fn run_translation_pass(
    inputs: &Groth16VerifyCompressedInput,
    primary_input_count: usize,
    credits: Vec<U24>,
    output_wires: Vec<WireId>,
) {
    let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(inputs);
    let mut metadata_mode = StreamingMode::<TranslationMode>::MetadataPass(root_meta);

    let metadata_start = Instant::now();
    // Run circuit construction in metadata mode
    let meta_output_wires = {
        let ok = groth16_verify_compressed(&mut metadata_mode, &allocated_inputs);
        vec![ok]
    };
    let metadata_time = metadata_start.elapsed();
    println!("Translation metadata time: {:?}", metadata_time);

    let meta_output_wires = meta_output_wires.iter().map(|&w| w).collect::<Vec<_>>();

    let (mut ctx, allocated_inputs) = metadata_mode.to_root_ctx(
        TranslationMode::new(
            credits,
            OUTPUT_FILE,
            primary_input_count as u64,
            output_wires.clone(),
        )
        .await,
        inputs,
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
        "Completed translation pass ({} inputs) in {:?}",
        allocated_inputs.public.len(),
        elapsed_translation
    );
    ctx.get_mut_mode().unwrap().finish();
}
