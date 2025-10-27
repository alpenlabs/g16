use ahash::{HashMap, HashMapExt};

use ckt::v5::a::reader::CircuitReaderV5a;
use cynosure::hints::unlikely;
use fixedbitset::FixedBitSet;
use indicatif::ProgressBar;

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/home/user/g16.ckt").unwrap();
    let mut available_wires = FixedBitSet::with_capacity(2usize.pow(34));
    for i in 0..reader.header().primary_inputs + 2 {
        available_wires.insert(i as usize);
    }
    let pb = ProgressBar::new(reader.header().total_gates());
    let mut wire_map = HashMap::new();
    let mut cur = 0;
    let always_available = reader.header().primary_inputs + 2;

    let lookup_wire = |map: &mut HashMap<u64, u32>, wire: u64| -> bool {
        if wire <= always_available {
            return true;
        }
        let mut credits = match map.get(&wire) {
            Some(credits) => *credits,
            None => return false,
        };
        credits -= 1;
        if credits == 0 {
            // if wire == 159314808 {
            //     println!("removing wire {}", wire);
            // }
            map.remove(&wire);
        } else {
            // if wire == 159314808 {
            //     println!("decrementing wire {} to {}", wire, credits);
            // }
            map.insert(wire, credits);
        }
        true
    };
    while let Some(block) = reader.next_block_soa().await.unwrap() {
        for i in 0..block.gates_in_block {
            // if block.in1[i] == 159314808 || block.in2[i] == 159314808 {
            //     println!("removing wire {}", wire);
            // }
            let in1_available = lookup_wire(&mut wire_map, block.in1[i]);
            let in2_available = lookup_wire(&mut wire_map, block.in2[i]);
            if unlikely(!in1_available) {
                panic!(
                    "Wire {cur} not possible: {} (NA) {} -> {}",
                    block.in1[i], block.in2[i], block.out[i]
                );
            } else if unlikely(!in2_available) {
                panic!(
                    "Wire {cur} not possible: {} {} (NA) -> {}",
                    block.in1[i], block.in2[i], block.out[i]
                );
            }
            available_wires.insert(block.out[i] as usize);
            wire_map.insert(block.out[i], block.credits[i]);
            cur += 1;
        }
        pb.inc(block.gates_in_block as u64);
    }
    pb.finish();
}
