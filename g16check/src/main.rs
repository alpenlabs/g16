use ckt::v5::a::reader::CircuitReaderV5a;
use cynosure::hints::unlikely;
use fixedbitset::FixedBitSet;
use indicatif::ProgressBar;

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/home/user/dev/alpen/g16/g16/g16.ckt").unwrap();
    let mut available_wires = FixedBitSet::with_capacity(2usize.pow(34));
    for i in 0..reader.header().primary_inputs + 4 {
        available_wires.insert(i as usize);
    }
    let pb = ProgressBar::new(reader.header().total_gates());
    let mut cur = 0;
    while let Some(block) = reader.next_block_soa().await.unwrap() {
        for i in 0..block.gates_in_block {
            let in1_available = available_wires.contains(block.in1[i] as usize);
            let in2_available = available_wires.contains(block.in2[i] as usize);
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
            cur += 1;
        }
        pb.inc(block.gates_in_block as u64);
    }
    pb.finish();
}
