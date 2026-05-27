# g16-pipeline

Generates a v5c boolean circuit (`v5c.ckt`) for the SP1 Groth16 verifier of a specific program, given the program's 32-byte vkey hash.

The pipeline does, in order:

1. Synthesize `compile_time.json` from the vkey hash + SP1 v6 standard constants.
2. `g16gen generate` → v5a circuit (subprocess).
3. `ckt-lvl::prealloc` → v5c circuit (in-process lib call).

The resulting v5c is unvalidated by this tool — exercising it against a real proof is the responsibility of the downstream consumer.

## Usage

From the `g16/` workspace:

```sh
cargo run -p g16-pipeline --release -- gen --vkey /path/to/vk.bin
```

Outputs land in `./pipeline-runs/run-YYYYMMDD-HHMMSS/`. A `pipeline-runs/latest` symlink (unix) points to the most recent successful run.

### Flags

| Flag                  | Default         | Notes                                                                                     |
| --------------------- | --------------- | ----------------------------------------------------------------------------------------- |
| `--vkey <path>`       | required        | Binary file containing the 32-byte SP1 program vkey hash (raw output of `bytes32_raw()`). |
| `--runs-dir <path>`   | `pipeline-runs` | Parent directory for run folders. Env: `G16_PIPELINE_RUNS`.                               |
| `--keep-intermediate` | off             | Keep `g16.ckt` (large v5a). Other files are kept regardless.                              |

### Run directory layout

```
pipeline-runs/run-20260513-152412/
├── v5c.ckt              ← the deliverable
├── compile_time.json
├── g16.ckt              ← deleted on success unless --keep-intermediate
└── summary.txt          ← per-step durations
```

On failure: nothing is cleaned, `latest` is not updated.

## Requirements on the SP1 program

These are properties of the verifier circuit (baked in by `g16gen`), not of the pipeline. The pipeline does not check them; the constraints surface downstream when proofs are run against the resulting circuit.

### `sp1-zkvm` must be built with the `blake3` feature

The g16 verifier circuit hashes `public_values` with blake3 (`g16ckt/src/gadgets/groth16.rs`). By default `sp1-zkvm` hashes them with SHA-256, so any proof generated without the blake3 feature will be rejected by the circuit.

Enable the feature in the **SP1 program's** `Cargo.toml` (the guest, not the host/script):

```toml
[dependencies]
sp1-zkvm = { ..., features = ["blake3"] }
```

This is a feature on `sp1-zkvm` (the guest entrypoint). At guest init it sets `PUBLIC_VALUES_HASHER = blake3::Hasher::new()` instead of `Sha256::new()` (`sp1-zkvm/src/lib.rs`).

### `public_values` must be exactly 36 bytes

`g16gen` hard-codes `INPUT_MESSAGE_LEN = 36` (`g16gen/src/circuit_args.rs`). Programs committing a different number of bytes need a g16gen change to parameterize the input length, or the circuit they produce will not match the proof shape.

## Producing `vk.bin`

A binary file containing the 32 raw bytes of the SP1 program's verifying-key hash. This is what `sp1_sdk::HashableKey::bytes32_raw()` returns — see the [sp1-sdk docs](https://docs.rs/sp1-sdk) and the SP1 [getting-started guide](https://docs.succinct.xyz/) for setting up a prover client and `setup`-ing your ELF.

```rust
use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};

let prover = ProverClient::from_env().await;
let pk = prover.setup(MY_PROGRAM_ELF).await.unwrap();
std::fs::write("vk.bin", pk.verifying_key().bytes32_raw()).unwrap();
```

`setup` does not generate a proof — only deriving the verifying key — so this is fast even for large programs.
