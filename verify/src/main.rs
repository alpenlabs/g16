use std::fs;

use ckt_fmtv5_types::v5::c::{ReaderV5c, verify_v5c_checksum};

// This utility checks a `v5c` circuit file's embedded SP1 verification key against a supplied key.
// If they match, it also verifies the file's checksum.
#[monoio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        panic!("incorrect number of arguments: verify path_to_file.v5c vkey.bin");
    }

    // First get and check the embedded header data
    let circuit_vk = ReaderV5c::open(&args[1]).unwrap().header().memo.to_vec();
    let supplied_vk = fs::read(&args[2]).unwrap();

    if circuit_vk == supplied_vk {
        println!("Verification keys match!");
    } else {
        eprintln!("Verification key mismatch detected!");
        eprintln!("Circuit vkey bytes: {:?}", circuit_vk);
        eprintln!("Supplied vkey bytes: {:?}", supplied_vk);
        panic!();
    }

    // Then verify the checksum
    println!("Verifying checksum...");
    if let Ok(true) = verify_v5c_checksum(&args[1]).await {
        println!("Verified!");
    } else {
        panic!("checksum verification failed");
    }
}
