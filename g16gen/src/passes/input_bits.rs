use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
};

use g16ckt::{WireId, circuit::CircuitInput, gadgets::groth16::Groth16VerifyCompressedRawInput};

const INPUT_BITS_FILE: &str = "inputs.txt";

/// Extract boolean input bits from Groth16VerifyCompressedInput and write to file
pub fn write_input_bits<const N: usize>(
    inputs: &Groth16VerifyCompressedRawInput<N>,
) -> std::io::Result<()> {
    let mut next_wire = 2;
    let input_wires = inputs.allocate(|| {
        let w = WireId(next_wire);
        next_wire += 1;
        w
    });
    let wire_ids = Groth16VerifyCompressedRawInput::collect_wire_ids(&input_wires);

    let mut bits = Vec::with_capacity(wire_ids.len());

    let public_bits: Vec<bool> = inputs
        .public
        .byte_arr
        .iter()
        .flat_map(|&b| (0..8).map(move |i| ((b >> i) & 1) == 1))
        .collect();
    bits.extend_from_slice(&public_bits);
    bits.extend_from_slice(&inputs.proof);

    // Verify we extracted the expected number of bits
    assert_eq!(
        bits.len(),
        wire_ids.len(),
        "Extracted {} bits but expected {} wire IDs",
        bits.len(),
        wire_ids.len()
    );

    // Write bits to file as '0' and '1' characters
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(INPUT_BITS_FILE)?;

    let mut writer = BufWriter::new(file);
    for bit in bits {
        writer.write_all(if bit { b"1" } else { b"0" })?;
    }
    writer.flush()?;

    println!("Wrote {} input bits to {}", wire_ids.len(), INPUT_BITS_FILE);

    Ok(())
}
