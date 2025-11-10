# G16

A streaming binary-circuit implementation of a Groth16 verifier over BN254. It targets large, real‑world verifier circuits while keeping memory bounded via a two‑pass streaming architecture. The crate supports execution modes to generate and dump the circuit configuration in an optimized file format.

**Background**
- **What:** Encode a SNARK verifier (Groth16 on BN254) as a binary circuit. The verifier’s elliptic‑curve and pairing arithmetic is expressed with reusable gadgets (Fq/Fr/Fq2/Fq6/Fq12, G1/G2, Miller loop, final exponentiation).

- **How:**
  - Keep field arithmetic in Montgomery form to minimize reductions and wire width churn; convert only at the edges when needed.
  - Run a two‑phase streaming pipeline: first collect a compact “shape” of wire lifetimes (credits), then execute once with precise allocation and immediate reclamation. During this execution phase, binary circuit representation is written to v5a file format.
  - Use level optimizer to generate a more optimal circuit format i.e. v5b which can later be shared in the network
  - Separate libraries will handle the rest of the flow i.e. read v5b circuit file, perform garbling, evaluation, Cut-and-Choose, etc.

**Intended Use**
- Explore/benchmark circuit representation on a non‑trivial circuit (Groth16 verifier).
- Reuse BN254 gadgets for experiments or educational purposes.
- Work with deterministic, testable building blocks that mirror arkworks semantics.

**Core Concepts**
- **WireId / Wires:** Logical circuit wires carried through streaming contexts; gadgets implement `WiresObject` to map rich types to wire vectors.
- **Modes:** `Execute` (booleans, for testing)
- **Components:** Functions annotated with `#[component]` become cached, nested circuit components; a component‑keyed template pool and a metadata pass compute per‑wire fanout totals and derive per‑wire "credits" (remaining‑use counters) for tight memory reuse.

**Terminology**
- **Fanout (total):** Total number of downstream reads/uses a wire will have within a component.
- **Credits (remaining):** The runtime counter that starts at the fanout total and is decremented on each read; when it reaches 1, the next read returns ownership and frees storage.

**Project Structure**
- `src/core`: fundamental types and logic (`S`, `Delta`, `WireId`, `Gate`, `GateType`).
- `src/circuit`: streaming builder, modes (`Execute`), finalization, and tests.
- `src/gadgets`: reusable gadgets: `bigint/u254`, BN254 fields and groups, pairing ops, and `groth16` verifier composition.
- `src/math`: focused math helpers (Montgomery helpers).
- `circuit_component_macro/`: proc‑macro crate backing `#[component]` ergonomics; trybuild tests live under `tests/`.

## API Overview

### 1. Streaming Garbling Architecture

The implementation uses a **streaming wire-based** circuit construction model that processes circuits incrementally to manage memory efficiently:

- **Wire-Based Model**: All computations flow through `WireId` references representing circuit wires. Wires are allocated incrementally and executed/written in streaming fashion, avoiding the need to hold the entire circuit in memory.

- **Component Hierarchy**: Circuits are organized as hierarchical components that track input/output wires and gate counts. Components support caching for wire reuse optimization.

- **Three Execution Modes**:
  - `Execute`: Direct boolean evaluation for testing correctness
  - `Credit`: todo
  - `Transport`: todo

### 2. Component Macro

The `#[component]` procedural macro transforms regular Rust functions into circuit component gadgets, automatically handling wire management and component nesting:

```rust
#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}

#[component]
fn full_adder(ctx: &mut impl CircuitContext, a: WireId, b: WireId, cin: WireId) -> (WireId, WireId) {
    let sum1 = xor_gate(ctx, a, b);
    let carry1 = and_gate(ctx, a, b);
    let sum = xor_gate(ctx, sum1, cin);
    let carry2 = and_gate(ctx, sum1, cin);
    let carry = or_gate(ctx, carry1, carry2);
    (sum, carry)
}
```

The macro automatically:
- Collects input parameters into wire lists
- Creates child components with proper input/output tracking
- Manages component caching and wire allocation
- Supports up to 16 input parameters

See `circuit_component_macro/` for details and compile‑time tests.

## Examples

### Prerequisites
- Rust toolchain (latest stable)
- Clone this repository

### Groth16 Verifier (Execute)

```bash
# Info logging for progress
RUST_LOG=info cargo run --example groth16_mpc --release

# Quieter/faster
cargo run --example groth16_mpc --release
```

Does:
- Generates a Groth16 proof with arkworks
- Verifies it using the streaming verifier (execute mode)
- Prints result and basic stats

### Focused Micro‑benchmarks
- `fq_inverse_many` – stress streaming overhead in Fq inverse gadgets.
- `g1_multiplexer_flame` – profile hot G1 multiplexer logic (works well with `cargo flamegraph`).

Note: Performance depends on the chosen example size and logging. The design focuses on scaling via streaming; larger gate counts benefit from the two‑pass allocator and component template cache.

## Current Status

- Groth16 verifier gadget implemented and covered by deterministic tests (true/false cases) using arkworks fixtures.
- Streaming modes: `Execute` is implemented with integration tests
- BN254 gadget suite: Fq/Fr/Fq2/Fq6/Fq12 arithmetic, G1/G2 group ops, Miller loop, and final exponentiation in Montgomery form.
- Component macro crate is integrated; trybuild tests validate signatures and errors.

Planned/ongoing work:
- Continue tuning the two‑pass allocator, component template LRU, and wire crediting to keep peak memory low at high gate counts.
- Extend examples and surface metrics (gate counts, memory, throughput) for reproducible performance tracking.

## Architecture Overview

```
src/
├── core/                 # S, Delta, WireId, Gate, GateType
├── circuit/              # Streaming builder, modes, finalization, tests
│   └── streaming/        # Two‑pass meta + execution, templates, modes
├── gadgets/              # Basic, bigint/u254, BN254 fields, groups, pairing, Groth16
└── math/                 # Montgomery helpers and small math utils

circuit_component_macro/  # #[component] proc‑macro + tests
```

## Testing

Run the test suite to verify component functionality:

```bash
# All unit/integration/macro tests
cargo test --workspace --all-targets

# Focus on Groth16 tests with output
RUST_BACKTRACE=1 cargo test test_groth16_verify -- --nocapture

# Release mode for heavy computations
cargo test --release
```

## Contributing

Contributions are welcome. If you find a bug, have an idea, or want to improve performance or documentation, please open an issue or submit a pull request. For larger changes, start a discussion in an issue first so we can align on the approach. Thank you for helping improve the project.
