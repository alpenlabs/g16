use std::{
    fs::OpenOptions,
    io::{BufReader, BufWriter, Read, Write},
};

use g16ckt::WireId;

const FANOUT_FILE: &str = "fanout.cache";
const OUTPUT_WIRES_FILE: &str = "outputs.cache";

/// Try to load cached fanout and output wires from files
pub fn try_load_cache() -> Option<(Vec<u16>, Vec<WireId>)> {
    let fanout = load_fanout()?;
    let output_wires = load_output_wires()?;
    Some((fanout, output_wires))
}

/// Load fanout from cache file
fn load_fanout() -> Option<Vec<u16>> {
    let file = OpenOptions::new().read(true).open(FANOUT_FILE).ok()?;
    let mut reader = BufReader::new(file);
    let mut fanout = Vec::new();

    loop {
        let mut buf = [0u8; 2];
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        fanout.push(u16::from_le_bytes(buf));
    }

    Some(fanout)
}

/// Load output wires from cache file
fn load_output_wires() -> Option<Vec<WireId>> {
    let file = OpenOptions::new().read(true).open(OUTPUT_WIRES_FILE).ok()?;
    let mut reader = BufReader::new(file);
    let mut output_wires = Vec::new();

    loop {
        let mut buf = [0u8; 8];
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        output_wires.push(WireId(usize::from_le_bytes(buf)));
    }

    Some(output_wires)
}

/// Save fanout to cache file
pub fn save_fanout(fanout: &[u16]) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(FANOUT_FILE)?;

    let mut writer = BufWriter::new(file);
    for fanout in fanout {
        writer.write_all(&fanout.to_le_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

/// Save output wires to cache file
pub fn save_output_wires(output_wires: &[WireId]) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(OUTPUT_WIRES_FILE)?;

    let mut writer = BufWriter::new(file);
    for output_wire in output_wires {
        writer.write_all(&output_wire.0.to_le_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

/// Save both credits and output wires to cache files
pub fn save_cache(credits: &[u16], output_wires: &[WireId]) -> std::io::Result<()> {
    save_fanout(credits)?;
    save_output_wires(output_wires)?;
    Ok(())
}
