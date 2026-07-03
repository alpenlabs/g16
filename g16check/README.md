# g16check - Validate `v5a` wire lifetimes

This tool takes a `v5a` circuit file and parses it, validating wire lifetimes.
Before doing this, it also verifies the file's checksum to ensure it hasn't been corrupted.

To use from the `g16` workspace:
```sh
cargo run -p g16check --release -- /path/to/circuit.v5a
```
