pub mod blake3;
// Unaudited, gate-optimized BLAKE3 gadget, kept for tests only so it cannot reach the production
// circuit
#[cfg(test)]
pub mod blake3_opt;
