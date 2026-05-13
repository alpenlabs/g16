# g16-pipeline

Generates and validates v5c boolean circuits (`v5c.ckt`) for the SP1 Groth16 verifier of a specific program. Two subcommands:

- **`gen`** — produce a v5c circuit. Two input modes:
  - `--proof`: full pipeline end-to-end, including a cleartext-exec sanity check that asserts the v5c verifier accepts the supplied proof.
  - `--vkey`: circuit-only mode for programs whose proofs take too long to generate. Synthesizes the circuit from the program's vkey hash plus SP1 v6 standard constants. No sanity check is possible without runtime proof inputs.
- **`validate`** — run only the cleartext-exec sanity check against an existing v5c using a fresh proof. Skips the expensive circuit-generation stages. Useful for validating a `--vkey`-generated circuit once a proof becomes available.

## Usage

From the `g16/` workspace:

```sh
# Generate, full pipeline (with sanity check)
cargo run -p g16-pipeline --release -- gen --proof /path/to/<program>_SP1_<version>.proof

# Generate, circuit-only (no proof yet)
cargo run -p g16-pipeline --release -- gen --vkey /path/to/vk.bin

# Validate an existing v5c against a fresh proof
cargo run -p g16-pipeline --release -- validate \
    --v5c pipeline-runs/latest/v5c.ckt \
    --proof /path/to/<program>_SP1_<version>.proof
```

Outputs land in `./pipeline-runs/run-YYYYMMDD-HHMMSS/`. A `pipeline-runs/latest` symlink (unix) points to the most recent successful run.

### Flags

`gen`:

| Flag                  | Default         | Notes                                                                                              |
| --------------------- | --------------- | -------------------------------------------------------------------------------------------------- |
| `--proof <path>`      | required¹       | zkaleido `ProofReceiptWithMetadata` file.                                                          |
| `--vkey <path>`       | required¹       | Binary file containing the 32-byte SP1 program vkey hash (raw output of `bytes32_raw()`).          |
| `--runs-dir <path>`   | `pipeline-runs` | Parent directory for run folders. Env: `G16_PIPELINE_RUNS`.                                        |
| `--keep-intermediate` | off             | Keep `g16.ckt` (large v5a). Other files are kept regardless.                                       |
| `--no-sanity-check`   | off             | Skip the cleartext-exec verification at the end (only relevant with `--proof`).                    |

¹ Exactly one of `--proof` / `--vkey` is required.

`validate`:

| Flag                | Default         | Notes                                                                  |
| ------------------- | --------------- | ---------------------------------------------------------------------- |
| `--v5c <path>`      | required        | Path to the v5c circuit to validate.                                   |
| `--proof <path>`    | required        | zkaleido `ProofReceiptWithMetadata` file (must be for the same program). |
| `--runs-dir <path>` | `pipeline-runs` | Parent directory for run folders. Env: `G16_PIPELINE_RUNS`.            |

### Pipeline stages

| Stage | `gen --proof` | `gen --vkey` | `validate` |
|---|---|---|---|
| Synth `compile_time.json` | ✓ | ✓ | — |
| `g16gen generate` → v5a | ✓ | ✓ | — |
| `ckt-lvl::prealloc` → v5c | ✓ | ✓ | — |
| Synth `run_time.json` + `g16gen write-input-bits` → `inputs.txt` | ✓ | — | ✓ |
| Cleartext-exec sanity check | ✓ | — | ✓ |

### Run directory layout

`gen`:

```
pipeline-runs/run-20260513-152412/
├── v5c.ckt              ← the deliverable
├── compile_time.json
├── run_time.json        ← only with --proof
├── inputs.txt           ← only with --proof
├── g16.ckt              ← deleted on success unless --keep-intermediate
└── summary.txt          ← per-step durations
```

`validate` (no new v5c; the supplied one is exercised in place):

```
pipeline-runs/run-20260513-152412/
├── run_time.json
├── inputs.txt
└── summary.txt
```

On failure: nothing is cleaned, `latest` is not updated.

## Requirements on the SP1 program

### `sp1-zkvm` must be built with the `blake3` feature

The g16 verifier circuit hashes `public_values` with blake3 (`g16ckt/src/gadgets/groth16.rs`). By default `sp1-zkvm` hashes them with SHA-256, so the proof's `committed_values_digest` does not match what the circuit computes and verification fails.

Enable the feature in the **SP1 program's** `Cargo.toml` (the guest, not the host/script):

```toml
[dependencies]
sp1-zkvm = { ..., features = ["blake3"] }
```

This is a feature on `sp1-zkvm` (the guest entrypoint). At guest init it sets `PUBLIC_VALUES_HASHER = blake3::Hasher::new()` instead of `Sha256::new()` (`sp1-zkvm/src/lib.rs:146`). The prover side picks it up automatically; both `pv.hash()` and `pv.blake3_hash()` are accepted (`sp1-sdk/src/prover.rs:187`).

### `public_values` must be exactly 36 bytes (enforced whenever a proof is supplied)

`g16gen` hard-codes `INPUT_MESSAGE_LEN = 36` (`g16gen/src/circuit_args.rs`). The pipeline validates this up front in `gen --proof` and `validate` modes and fails fast otherwise. `gen --vkey` mode does not have access to `public_values` and cannot enforce this; a length mismatch surfaces later under `validate`.

## Producing the input files

### `vk.bin` (`gen --vkey`)

A binary file containing the 32 raw bytes of the SP1 program's verifying-key hash. This is what `sp1_sdk::HashableKey::bytes32_raw()` returns — see the [sp1-sdk docs](https://docs.rs/sp1-sdk) and the SP1 [getting-started guide](https://docs.succinct.xyz/) for setting up a prover client and `setup`-ing your ELF.

```rust
use sp1_sdk::{HashableKey, Prover, ProverClient};

let prover = ProverClient::from_env().await;
let pk = prover.setup(MY_PROGRAM_ELF).await.unwrap();
std::fs::write("vk.bin", pk.verifying_key().bytes32_raw()).unwrap();
```

`setup` does not generate a proof — only deriving the verifying key — so this is fast even for large programs.

### Proof file (`gen --proof`, `validate --proof`)

zkaleido `ProofReceiptWithMetadata` format, not SP1's raw `proof.bytes()`. The prover-side code wraps the SP1 output before saving:

```toml
zkaleido = { git = "https://github.com/alpenlabs/zkaleido", default-features = false }
```

```rust
use sp1_sdk::HashableKey;
use zkaleido::{
    ProgramId, Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata,
    ProofType, PublicValues, ZkVm,
};

let receipt = ProofReceiptWithMetadata::new(
    ProofReceipt::new(
        Proof::new(proof.bytes()),
        PublicValues::new(proof.public_values.as_slice().to_vec()),
    ),
    ProofMetadata::new(
        ZkVm::SP1,
        ProgramId(pk.verifying_key().bytes32_raw()),
        proof.sp1_version.clone(),
        ProofType::Groth16,
    ),
);
receipt.save("<program-name>")?;  // writes "<program-name>_SP1_<version>.proof"
```
