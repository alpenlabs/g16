use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
};

use g16ckt::{
    WireId,
    circuit::CircuitInput,
    gadgets::{bigint::BigIntWires, groth16::Groth16VerifyCompressedInput},
};

const INPUT_BITS_FILE: &str = "inputs.txt";

/// Extract boolean input bits from Groth16VerifyCompressedInput and write to file
pub fn write_input_bits(inputs: &Groth16VerifyCompressedInput) -> std::io::Result<()> {
    let mut next_wire = 2;
    let input_wires = inputs.allocate(|| {
        let w = WireId(next_wire);
        next_wire += 1;
        w
    });
    let wire_ids = Groth16VerifyCompressedInput::collect_wire_ids(&input_wires);

    let mut bits = Vec::with_capacity(wire_ids.len());

    // Extract public field element bits
    for (wire_repr, value) in input_wires.public.iter().zip(inputs.public.iter()) {
        let bits_fn = BigIntWires::get_wire_bits_fn(wire_repr, value)
            .expect("Failed to get bits function for public input");

        for &wire_id in wire_repr.iter() {
            if let Some(bit) = bits_fn(wire_id) {
                bits.push(bit);
            }
        }
    }

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
