use crate::u24::U24;
use g16ckt::WireId;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Write};

const CREDITS_FILE: &str = "credits.cache";
const OUTPUT_WIRES_FILE: &str = "outputs.cache";

/// Try to load cached credits and output wires from files
pub fn try_load_cache() -> Option<(Vec<U24>, Vec<WireId>)> {
    let credits = load_credits()?;
    let output_wires = load_output_wires()?;
    Some((credits, output_wires))
}

/// Load credits from cache file
fn load_credits() -> Option<Vec<U24>> {
    let file = OpenOptions::new().read(true).open(CREDITS_FILE).ok()?;
    let mut reader = BufReader::new(file);
    let mut credits = Vec::new();

    loop {
        let mut buf = [0u8; 3];
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        credits.push(U24::new(buf));
    }

    Some(credits)
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

/// Save credits to cache file
pub fn save_credits(credits: &[U24]) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(CREDITS_FILE)?;

    let mut writer = BufWriter::new(file);
    for credit in credits {
        writer.write_all(&credit.to_bytes())?;
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
pub fn save_cache(credits: &[U24], output_wires: &[WireId]) -> std::io::Result<()> {
    save_credits(credits)?;
    save_output_wires(output_wires)?;
    Ok(())
}
