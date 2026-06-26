# g16-pipeline

Generates and validates v5c boolean circuits (`v5c.ckt`) for the SP1 Groth16 verifier of a specific program.

- **`gen --vkey`** — synthesize a v5c from the 32-byte vkey hash + SP1 v6 constants. No proof needed; the result is unvalidated.
- **`validate-proof`** — sanity-check an existing v5c against a raw SP1 v6 prover artifact (bincode `SP1ProofWithPublicValues`, what `proof.save(...)` writes). Skips circuit generation.

## Usage

From the `g16/` workspace:

```sh
cargo run -p g16-pipeline --release -- gen --vkey /path/to/vk.bin
cargo run -p g16-pipeline --release -- validate-proof --v5c <v5c> --proof <sp1-artifact>
```

`gen` writes to `pipeline-runs/run-YYYYMMDD-HHMMSS/`; `validate-proof` writes to `validation-runs/run-YYYYMMDD-HHMMSS/`. Each parent maintains its own `latest` symlink (unix). Override the parent with `--runs-dir` or env (`G16_PIPELINE_RUNS`, `G16_VALIDATION_RUNS`).

`gen` also takes `--keep-intermediate` (preserve `g16.ckt`, the large v5a).

### Run directory layout

```
pipeline-runs/run-…/      validation-runs/run-…/
├── v5c.ckt               ├── run_time.json
├── compile_time.json     ├── inputs.txt
├── g16.ckt †             └── summary.txt
└── summary.txt
```

† deleted on success unless `--keep-intermediate`.

On failure: nothing is cleaned, `latest` is not updated.

**Note**: Runs should not be done in parallel in the same `runs_dir` in order to avoid unexpected behavior or failed runs.

## Requirements on the SP1 program

These are properties of the verifier circuit (baked in by `g16gen`).

### `sp1-zkvm` must be built with the `blake3` feature

The g16 verifier circuit hashes `public_values` with blake3 (`g16ckt/src/gadgets/groth16.rs`). By default `sp1-zkvm` hashes them with SHA-256, so any proof generated without the blake3 feature will be rejected by the circuit.

Enable the feature in the **SP1 program's** `Cargo.toml` (the guest, not the host/script):

```toml
[dependencies]
sp1-zkvm = { ..., features = ["blake3"] }
```

### `public_values` must be exactly 36 bytes

`g16gen` hard-codes `INPUT_MESSAGE_LEN = 36` (`g16gen/src/circuit_args.rs`). `validate-proof` fails fast on a length mismatch; `gen --vkey` cannot check it.

## Producing the input files

### `vk.bin` (`gen --vkey`)

A binary file containing the 32 raw bytes of `sp1_sdk::HashableKey::bytes32_raw()`:

```rust
let prover = ProverClient::from_env().await;
let pk = prover.setup(MY_PROGRAM_ELF).await.unwrap();
std::fs::write("vk.bin", pk.verifying_key().bytes32_raw()).unwrap();
```

`setup` does not generate a proof, so this is fast even for large programs.

### Raw SP1 proof file (`validate-proof --proof`)

The bincode artifact `SP1ProofWithPublicValues::save(...)` writes directly — no zkaleido wrapper. Either format the matching `::load(...)` accepts works (post-network or `ProofFromNetwork`). Must be `SP1ProofMode::Groth16`; other modes are rejected with a clear error.
