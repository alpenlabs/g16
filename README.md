# Garbled SNARK Verifier Circuit

This repository implements a garbled circuit groth16 verifier and represents it as a v5a circuit.

## Project Structure

circuit_component_macro - macro component used by g16ckt

g16ckt - Binary circuit implementation of groth16 verifier

g16gen - Represent binary circuit as in v5a format

verify - Verify integrity of v5a file

## Getting Started

Run the following to generate and test binary circuit for SP1's groth16 verifier
```bash
cargo test --release --package g16ckt --lib -- gadgets::groth16::tests::test_groth16_verify_compressed_true_small_using_mock_sp1_proof_in_gnark_format --exact --nocapture
```

Follow guidelines in g16gen/README.md to generate v5a file.

## Acknowledgements
The g16ckt crate is a snapshot of [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier) from the BitVM Alliance with audit fixes and SP1 verifier integration added on top.
