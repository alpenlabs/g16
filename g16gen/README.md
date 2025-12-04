# g16gen - Groth16 Boolean Circuit Generator

A tool for generating boolean circuits that encode a Groth16 proof verifier, and for extracting the boolean input bits needed to evaluate those circuits.

## Overview

`g16gen` generates a **boolean circuit** that encodes the logic of a **Groth16 proof verifier**. The circuit consists of boolean gates (AND, XOR, NOT) that implement all operations needed to verify a Groth16 proof: field arithmetic, elliptic curve operations, and pairing computations over the BN254 curve.

The tool supports two main operations:

1. **Circuit Generation**: Creates a complete boolean gate-level circuit file (`.ckt`) encoding a Groth16 proof verifier, with optimized wire ordering based on usage credits
2. **Input Bits Extraction**: Extracts the boolean input bits that encode a specific Groth16 proof (proof points A, B, C) and its public inputs
</text>

<old_text line=96>
## Implementation Details

## Project Structure

```
g16gen/
├── src/
│   ├── main.rs              # CLI entry point and command handling
│   ├── cache.rs             # Credits and output wires caching
│   ├── dummy_circuit.rs     # Test circuit for proof generation
│   ├── proof_setup.rs       # Test proof generation utilities
│   ├── modes/               # Circuit evaluation modes
│   │   ├── credit.rs        # Credit collection mode
│   │   └── translate.rs     # Circuit translation mode
│   └── passes/              # Circuit generation passes
│       ├── credits.rs       # Credits computation pass
│       ├── translation.rs   # Circuit translation pass
│       └── input_bits.rs    # Input bits extraction
```

## Commands

### `generate [k]`

Generates a boolean circuit file encoding a Groth16 proof verifier as a sequence of boolean gates.

**Arguments:**
- `k` (optional): Constraint size parameter. Creates a circuit with 2^k constraints. Default: 6

**Output:**
- `g16.ckt` - The boolean circuit file containing the gate-level encoding of the Groth16 verifier
- `credits.cache` - Wire credits cache (for future runs)
- `outputs.cache` - Output wires cache (for future runs)

**Example:**
```bash
# Generate circuit with 2^6 = 64 constraints
g16gen generate 6

# Generate circuit with 2^10 = 1024 constraints
g16gen generate 10
```

**Process:**
1. Generates a test Groth16 proof with the specified constraint size
2. Runs the credits pass to compute wire credits (cached for reuse)
3. Runs the translation pass to generate the boolean circuit file with gate encodings

### `write-input-bits [k]`

Extracts the boolean input values from a Groth16 proof and writes them to a file.

**Arguments:**
- `k` (optional): Constraint size parameter. Creates a proof with 2^k constraints. Default: 6

**Output:**
- `input_bits.txt` - UTF-8 file containing '0' and '1' characters representing the boolean inputs

**Example:**
```bash
# Write input bits for a 2^6 constraint circuit
g16gen write-input-bits 6

# Write input bits for a 2^8 constraint circuit
g16gen write-input-bits 8
```

**Input Structure:**

The input bits represent a specific Groth16 proof encoded as boolean values. They are extracted from the compressed Groth16 verification inputs in the following order:

1. **Public Inputs** (Fr field elements): Each public input is encoded as 254 bits (BN254 Fr field size)
2. **Proof Point A** (G1): Compressed x-coordinate (254 bits) + y-flag (1 bit)
3. **Proof Point B** (G2): Compressed x-coordinate (508 bits, Fq2) + y-flag (1 bit)
4. **Proof Point C** (G1): Compressed x-coordinate (254 bits) + y-flag (1 bit)

All bits are in little-endian order within each field element.

### `help`

Displays usage information.

```bash
g16gen help
```

## Implementation Details

### Caching

The circuit generation process uses caching to avoid redundant computation:

- **credits.cache**: Stores computed wire credits (3 bytes per wire)
- **outputs.cache**: Stores output wire IDs (8 bytes per wire)

If these files exist, the credits pass is skipped and cached values are used instead.

### Input Bits Extraction

The `write-input-bits` command extracts boolean values by:

1. Allocating wire IDs for the compressed Groth16 inputs
2. Converting field elements and curve points to their bit representations
3. Using Montgomery form for field arithmetic
4. Computing y-coordinate compression flags for elliptic curve points

The extraction process mirrors the encoding logic used during circuit evaluation, ensuring the bits match what the boolean gates expect as inputs.

### Passes

The circuit generation happens in two passes:

1. **Credits Pass**: Computes the number of "credits" (future references) for each wire in the boolean circuit
2. **Translation Pass**: Translates the high-level circuit representation into a boolean gate-level format (`.ckt` file), using credits to optimize wire ordering

## Development

Build the project:
```bash
cargo build --release -p g16gen
```

Run with logging:
```bash
RUST_LOG=info ./target/release/g16gen generate 6
```

## Circuit Format

The generated `.ckt` file contains:
- **Header**: Number of input wires, output wires, total wires, and gates
- **Gate definitions**: Each gate specifies its type (AND/XOR/NOT), input wire IDs, and output wire ID
- **Wire ordering**: Optimized based on credits to minimize memory usage during evaluation

The file format is designed for efficient evaluation in garbled circuit protocols.

## Notes

- The test proofs use a seeded RNG (seed: 12345) for deterministic results
- All inputs use the BN254 elliptic curve (254-bit prime field) and its associated scalar field Fr
- Compressed points use the standard compression format: x-coordinate (Montgomery form) + y-sign bit
- The circuit encodes all arithmetic in binary (bit-level) representation
- Typical circuit size: ~1-2 million gates for a single Groth16 verification
