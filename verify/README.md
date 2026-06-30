# verify - Check a circuit file against an SP1 key

This tool takes a circuit file and checks it against a supplied SP1 verification key.

Given a `v5c` circuit file and SP1 verification key, it:
- Checks that the supplied key matches the key embedded into the circuit file header
- Validates the circuit file checksum

To use from the `g16` workspace:
```sh
cargo run -p verify --release -- /path/to/circuit.v5c /path/to/sp1_vk.bin
```
