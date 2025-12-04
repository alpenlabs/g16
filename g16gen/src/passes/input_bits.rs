use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
};

use g16ckt::{
    Fq2Wire, WireId,
    ark::{CurveGroup, Field},
    circuit::CircuitInput,
    gadgets::{
        bn254::{fq::Fq, fr::Fr},
        groth16::Groth16VerifyCompressedInput,
    },
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
    for (wire_repr, value) in input_wires.public.iter().zip(inputs.0.public.iter()) {
        let bits_fn = Fr::get_wire_bits_fn(wire_repr, value)
            .expect("Failed to get bits function for public input");

        for &wire_id in wire_repr.iter() {
            if let Some(bit) = bits_fn(wire_id) {
                bits.push(bit);
            }
        }
    }

    // Extract compressed point A (x-coordinate + y-flag)
    let a_aff_std = inputs.0.a.into_affine();
    let a_x_m = Fq::as_montgomery(a_aff_std.x);
    let a_flag = (a_aff_std.y.square())
        .sqrt()
        .expect("y^2 must be QR")
        .eq(&a_aff_std.y);

    let a_x_fn = Fq::get_wire_bits_fn(&input_wires.a.x_m, &a_x_m)
        .expect("Failed to get bits function for point A x-coordinate");

    for &wire_id in input_wires.a.x_m.iter() {
        if let Some(bit) = a_x_fn(wire_id) {
            bits.push(bit);
        }
    }
    bits.push(a_flag);

    // Extract compressed point B (x-coordinate + y-flag)
    let b_aff_std = inputs.0.b.into_affine();
    let b_x_m = Fq2Wire::as_montgomery(b_aff_std.x);
    let b_flag = (b_aff_std.y.square())
        .sqrt()
        .expect("y^2 must be QR in Fq2")
        .eq(&b_aff_std.y);

    let b_x_fn = Fq2Wire::get_wire_bits_fn(&input_wires.b.p, &b_x_m)
        .expect("Failed to get bits function for point B x-coordinate");

    for &wire_id in input_wires.b.p.iter() {
        if let Some(bit) = b_x_fn(wire_id) {
            bits.push(bit);
        }
    }
    bits.push(b_flag);

    // Extract compressed point C (x-coordinate + y-flag)
    let c_aff_std = inputs.0.c.into_affine();
    let c_x_m = Fq::as_montgomery(c_aff_std.x);
    let c_flag = (c_aff_std.y.square())
        .sqrt()
        .expect("y^2 must be QR")
        .eq(&c_aff_std.y);

    let c_x_fn = Fq::get_wire_bits_fn(&input_wires.c.x_m, &c_x_m)
        .expect("Failed to get bits function for point C x-coordinate");

    for &wire_id in input_wires.c.x_m.iter() {
        if let Some(bit) = c_x_fn(wire_id) {
            bits.push(bit);
        }
    }
    bits.push(c_flag);

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
