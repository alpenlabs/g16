# Groth16 Boolean Verifier Circuit

This repository represents the **SP1 v6** Groth16 proof verifier as a boolean circuit. A `pipeline` crate drives the end-to-end flow from an SP1 program vkey hash to a v5c boolean circuit ready for downstream use. The v5a/v5c circuit formats are defined in the [alpenlabs/ckt](https://github.com/alpenlabs/ckt) repository.

## Project Structure

pipeline - End-to-end driver: SP1 program vkey hash → v5c boolean circuit (the entry point)

circuit_component_macro - macro component used by g16ckt

g16ckt - Binary circuit implementation of groth16 verifier

g16gen - Represent binary circuit as in v5a format

verify - Verify integrity of v5a file

g16check - Walk a v5a circuit and validate wire lifetimes

## Getting Started

The `pipeline` crate is the main entry point. Given a 32-byte SP1 program vkey hash, it generates the SP1 Groth16 verifier as a v5c boolean circuit:

```bash
cargo run -p g16-pipeline --release -- gen --vkey /path/to/vk.bin
```

Output lands in `./pipeline-runs/run-YYYYMMDD-HHMMSS/v5c.ckt`. See [`pipeline/README.md`](pipeline/README.md) for flags, how to produce `vk.bin`, and the SP1 program requirements (the guest must enable the `sp1-zkvm` `blake3` feature, and `public_values` must be 36 bytes).

For the lower-level v5a generation commands invoked by the pipeline, see [`g16gen/README.md`](g16gen/README.md).

## Acknowledgements

The g16ckt crate is a snapshot of [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier) from the BitVM Alliance with audit fixes and SP1 verifier integration added on top.
