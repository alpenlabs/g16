//! Gate-optimized binary circuit implementation of the BLAKE3 hash
//!
//! UNAUDITED RESEARCH CODE. This is a parallel copy of [`super::blake3`] that folds constant
//! inputs and skips unused outputs to reduce the garbled gate cost. It is compiled for tests only
//! and is not used by the Groth16 verifier, so it does not change the production circuit.
//!
//! It shares the input and output types of [`super::blake3`], and has the same restriction to
//! messages of at most 1024 bytes. Unlike [`super::blake3`], it hashes an empty message to the
//! correct digest as constant output wires, `TRUE_WIRE` and `FALSE_WIRE`, rather than gate
//! outputs, since no input wire is involved. Code that uses the hash inside a component must not
//! fold on these constants; see the bit helpers below.
//! Implementation referenced from: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
//! Test Vector referenced from: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json

use core::{array, cmp::min};

use super::blake3::{HashOutputWires, InputMessageWires, U8};
use crate::{
    CircuitContext, Gate, WireId,
    circuit::{FALSE_WIRE, TRUE_WIRE},
};

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const ROOT: u32 = 1 << 3;

// Bit-level helpers that fold constant inputs instead of emitting gates.
//
// Much of the BLAKE3 state is known when the circuit is built: the IV, counter, block length,
// flags and zero padding. Since g16gen translates every gate into v5 AND/XOR, these helpers emit
// only `And` and `Xor` gates, with negation as XOR against `TRUE_WIRE`.
//
// Only the gadget's own constants are folded, tracked as `Bit::Const`. Input wires are always
// `Bit::Wire`, even when they are `TRUE_WIRE` or `FALSE_WIRE`, and two wires are never folded
// even when they are the same wire. StreamingMode builds a component's credit template from fresh,
// distinct, nonconstant mock inputs, so the emitted gates must not depend on which wires are passed
// in.

#[derive(Debug, Clone, Copy)]
enum Bit {
    Const(bool),
    Wire(WireId),
}

impl Bit {
    fn as_constant(self) -> Option<bool> {
        match self {
            Bit::Const(b) => Some(b),
            Bit::Wire(_) => None,
        }
    }

    fn to_wire(self) -> WireId {
        match self {
            Bit::Const(false) => FALSE_WIRE,
            Bit::Const(true) => TRUE_WIRE,
            Bit::Wire(w) => w,
        }
    }
}

fn not_bit<C: CircuitContext>(circuit: &mut C, a: Bit) -> Bit {
    match a {
        Bit::Const(a) => Bit::Const(!a),
        Bit::Wire(a) => {
            let res = circuit.issue_wire();
            circuit.add_gate(Gate::xor(a, TRUE_WIRE, res));
            Bit::Wire(res)
        }
    }
}

fn xor_bit<C: CircuitContext>(circuit: &mut C, a: Bit, b: Bit) -> Bit {
    match (a, b) {
        (Bit::Const(a), Bit::Const(b)) => Bit::Const(a ^ b),
        (Bit::Const(false), w) | (w, Bit::Const(false)) => w,
        (Bit::Const(true), w) | (w, Bit::Const(true)) => not_bit(circuit, w),
        (Bit::Wire(a), Bit::Wire(b)) => {
            let res = circuit.issue_wire();
            circuit.add_gate(Gate::xor(a, b, res));
            Bit::Wire(res)
        }
    }
}

fn and_bit<C: CircuitContext>(circuit: &mut C, a: Bit, b: Bit) -> Bit {
    match (a, b) {
        (Bit::Const(a), Bit::Const(b)) => Bit::Const(a & b),
        (Bit::Const(false), _) | (_, Bit::Const(false)) => Bit::Const(false),
        (Bit::Const(true), w) | (w, Bit::Const(true)) => w,
        (Bit::Wire(a), Bit::Wire(b)) => {
            let res = circuit.issue_wire();
            circuit.add_gate(Gate::and(a, b, res));
            Bit::Wire(res)
        }
    }
}

/// Full adder returning (sum, carry), with at most one AND gate.
fn add_bits<C: CircuitContext>(circuit: &mut C, a: Bit, b: Bit, c: Bit) -> (Bit, Bit) {
    let inputs = [a, b, c];
    let constants: Vec<bool> = inputs.iter().filter_map(|w| w.as_constant()).collect();
    let wires: Vec<Bit> = inputs
        .into_iter()
        .filter(|w| w.as_constant().is_none())
        .collect();

    match (constants.as_slice(), wires.as_slice()) {
        // No gates: all inputs are constant
        (&[a, b, c], []) => (Bit::Const(a ^ b ^ c), Bit::Const((a & b) | (c & (a ^ b)))),
        // At most one NOT: majority(k, k, x) = k and majority(0, 1, x) = x
        (&[k1, k2], &[x]) => {
            let sum = if k1 ^ k2 { not_bit(circuit, x) } else { x };
            let carry = if k1 == k2 { Bit::Const(k1) } else { x };
            (sum, carry)
        }
        // majority(0, x, y) = x & y and majority(1, x, y) = x | y = (x ^ y) ^ (x & y)
        (&[k], &[x, y]) => {
            let x_xor_y = xor_bit(circuit, x, y);
            let x_and_y = and_bit(circuit, x, y);
            if k {
                (
                    not_bit(circuit, x_xor_y),
                    xor_bit(circuit, x_xor_y, x_and_y),
                )
            } else {
                (x_xor_y, x_and_y)
            }
        }
        // carry = c ^ ((a ^ c) & (b ^ c))
        _ => {
            let a_xor_c = xor_bit(circuit, a, c);
            let b_xor_c = xor_bit(circuit, b, c);
            let sum = xor_bit(circuit, a, b_xor_c);
            let t = and_bit(circuit, a_xor_c, b_xor_c);
            (sum, xor_bit(circuit, c, t))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct U32([Bit; 32]);

impl U32 {
    fn from_constant(n: u32) -> U32 {
        U32(array::from_fn(|i| Bit::Const((n >> i) & 1 == 1)))
    }

    fn xor<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
        U32(array::from_fn(|i| xor_bit(circuit, a.0[i], b.0[i])))
    }

    fn rotate_right(value: U32, n: u32) -> U32 {
        let mut result = [Bit::Const(false); 32];
        let shift = (n % 32) as usize;

        for (i, result_i) in result.iter_mut().enumerate() {
            // Compute the new position using modular arithmetic
            let from_index = (i + shift) % 32;
            *result_i = value.0[from_index];
        }

        U32(result)
    }

    fn wrapping_add<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
        let mut result = [Bit::Const(false); 32];
        let mut carry = Bit::Const(false);

        for (i, result_i) in result.iter_mut().take(31).enumerate() {
            (*result_i, carry) = add_bits(circuit, a.0[i], b.0[i], carry);
        }
        // The carry out of the top bit is discarded, so only its sum is computed
        let a_xor_b = xor_bit(circuit, a.0[31], b.0[31]);
        result[31] = xor_bit(circuit, a_xor_b, carry);

        U32(result)
    }
}

fn get_iv() -> [U32; 8] {
    let iv2: [U32; 8] = [
        U32::from_constant(0x6A09E667),
        U32::from_constant(0xBB67AE85),
        U32::from_constant(0x3C6EF372),
        U32::from_constant(0xA54FF53A),
        U32::from_constant(0x510E527F),
        U32::from_constant(0x9B05688C),
        U32::from_constant(0x1F83D9AB),
        U32::from_constant(0x5BE0CD19),
    ];
    iv2
}

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// The mixing function, G, which mixes either a column or a diagonal.
#[allow(clippy::too_many_arguments)]
fn g<C: CircuitContext>(
    circuit: &mut C,
    state: &mut [U32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: U32,
    my: U32,
) {
    let tmp0 = U32::wrapping_add(circuit, state[a], state[b]);
    state[a] = U32::wrapping_add(circuit, tmp0, mx);
    state[d] = U32::rotate_right(U32::xor(circuit, state[d], state[a]), 16);
    state[c] = U32::wrapping_add(circuit, state[c], state[d]);
    state[b] = U32::rotate_right(U32::xor(circuit, state[b], state[c]), 12);

    let tmp0 = U32::wrapping_add(circuit, state[a], state[b]);
    state[a] = U32::wrapping_add(circuit, tmp0, my);
    state[d] = U32::rotate_right(U32::xor(circuit, state[d], state[a]), 8);
    state[c] = U32::wrapping_add(circuit, state[c], state[d]);
    state[b] = U32::rotate_right(U32::xor(circuit, state[b], state[c]), 7);
}

fn round<C: CircuitContext>(circuit: &mut C, state: &mut [U32; 16], m: &[U32; 16]) {
    // Mix the columns.
    g(circuit, state, 0, 4, 8, 12, m[0], m[1]);
    g(circuit, state, 1, 5, 9, 13, m[2], m[3]);
    g(circuit, state, 2, 6, 10, 14, m[4], m[5]);
    g(circuit, state, 3, 7, 11, 15, m[6], m[7]);
    // Mix the diagonals.
    g(circuit, state, 0, 5, 10, 15, m[8], m[9]);
    g(circuit, state, 1, 6, 11, 12, m[10], m[11]);
    g(circuit, state, 2, 7, 8, 13, m[12], m[13]);
    g(circuit, state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [U32; 16]) {
    let mut permuted = [U32([Bit::Const(false); 32]); 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i] as usize];
    }
    *m = permuted;
}

fn compress<C: CircuitContext>(
    circuit: &mut C,
    chaining_value: &[U32; 8],
    block_words: &[U32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [U32; 8] {
    let counter_low = U32::from_constant(counter as u32);
    let counter_high = U32::from_constant((counter >> 32) as u32);
    #[rustfmt::skip]
    let iv: [U32; 8] = get_iv();
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        iv[0],
        iv[1],
        iv[2],
        iv[3],
        counter_low,
        counter_high,
        U32::from_constant(block_len),
        U32::from_constant(flags),
    ];

    let mut block = *block_words;

    round(circuit, &mut state, &block); // round 1
    permute(&mut block);
    round(circuit, &mut state, &block); // round 2
    permute(&mut block);
    round(circuit, &mut state, &block); // round 3
    permute(&mut block);
    round(circuit, &mut state, &block); // round 4
    permute(&mut block);
    round(circuit, &mut state, &block); // round 5
    permute(&mut block);
    round(circuit, &mut state, &block); // round 6
    permute(&mut block);
    round(circuit, &mut state, &block); // round 7

    // Only the first 8 output words are needed: they are both the chaining value and the 32-byte
    // hash, so the second half (state[i + 8] ^ chaining_value[i]) is never computed.
    array::from_fn(|i| U32::xor(circuit, state[i], state[i + 8]))
}

/// A byte of the message or the block buffer, least significant bit first.
type Byte = [Bit; 8];

fn words_from_little_endian_bytes(bytes: &[Byte], words: &mut [U32]) {
    debug_assert_eq!(bytes.len(), 4 * words.len());
    for (four_bytes, word) in bytes.chunks_exact(4).zip(words) {
        let bit_vec: Vec<Bit> = four_bytes.iter().flatten().copied().collect();
        let app_four_bytes: U32 = U32(bit_vec.try_into().unwrap());
        *word = app_four_bytes;
    }
}

struct Output {
    input_chaining_value: [U32; 8],
    block_words: [U32; 16],
    block_len: u32,
    flags: u32,
}

impl Output {
    fn root_output_bytes<C: CircuitContext>(&self, circuit: &mut C, out: &mut [U8; OUT_LEN]) {
        let words = compress(
            circuit,
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        for (word_bits, out_word_bits) in words.iter().zip(out.chunks_mut(4)) {
            for (i, byte_bits) in out_word_bits.iter_mut().enumerate() {
                *byte_bits = U8(array::from_fn(|j| word_bits.0[8 * i + j].to_wire()));
            }
        }
    }
}

struct ChunkState {
    chaining_value: [U32; 8],
    chunk_counter: u64,
    block: [Byte; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [U32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [[Bit::Const(false); 8]; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update<C: CircuitContext>(&mut self, circuit: &mut C, mut input: &[Byte]) {
        let zero_bit = Bit::Const(false);
        while !input.is_empty() {
            // If the block buffer is full, compress it and clear it. More
            // input is coming, so this compression is not CHUNK_END.
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [U32([zero_bit; 32]); 16];
                words_from_little_endian_bytes(&self.block, &mut block_words);
                self.chaining_value = compress(
                    circuit,
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.blocks_compressed += 1;
                self.block = [[zero_bit; 8]; BLOCK_LEN];
                self.block_len = 0;
            }

            // Copy input bytes into the block buffer.
            let want = BLOCK_LEN - self.block_len as usize;
            let take = min(want, input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let zero_bit = Bit::Const(false);
        let mut block_words = [U32([zero_bit; 32]); 16];
        words_from_little_endian_bytes(&self.block, &mut block_words);

        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/// An incremental hasher that can accept any number of writes.
pub(crate) struct Hasher {
    chunk_state: ChunkState,
}

impl Hasher {
    fn new_internal(key_words: [U32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
        }
    }

    /// Construct a new `Hasher` for the regular hash function.
    pub(crate) fn new() -> Self {
        Self::new_internal(get_iv(), 0)
    }

    /// Add input to the hash state.
    fn update<C: CircuitContext>(&mut self, circuit: &mut C, mut input: &[Byte]) {
        while !input.is_empty() {
            // Compress input bytes into the current chunk state.
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = min(want, input.len());
            self.chunk_state.update(circuit, &input[..take]);
            input = &input[take..];
        }
    }

    /// Finalize the hash and write the 32-byte output.
    fn finalize<C: CircuitContext>(&self, circuit: &mut C, out: &mut [U8; OUT_LEN]) {
        self.chunk_state.output().root_output_bytes(circuit, out);
    }
}

/// The function generates 32 byte output hash for given input message
pub fn blake3_hash<const N: usize, C: CircuitContext>(
    circuit: &mut C,
    input_message_bytes: InputMessageWires<N>,
) -> HashOutputWires {
    assert!(
        input_message_bytes.byte_arr.len() <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    // Input wires are never folded, even when they are constants
    let message: Vec<Byte> = input_message_bytes
        .byte_arr
        .iter()
        .map(|byte| byte.0.map(Bit::Wire))
        .collect();
    let mut hasher = Hasher::new();
    hasher.update(circuit, &message);

    let mut hash = [U8([FALSE_WIRE; 8]); OUT_LEN];
    hasher.finalize(circuit, &mut hash);
    HashOutputWires { value: hash }
}

#[cfg(test)]
mod test {

    use std::{fs::File, io::BufReader, str::FromStr};

    use blake3::CHUNK_LEN;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::blake3_hash;
    use crate::{
        circuit::CircuitBuilder,
        gadgets::hash::blake3::{self as audited, HashOutput, InputMessage},
    };

    fn validate_blake3_hash_for_input<const N: usize>(inputs: InputMessage<N>) {
        let mut ref_hasher = blake3::Hasher::new();
        ref_hasher.update(&inputs.byte_arr);
        let ref_hash = ref_hasher.finalize();
        let ref_hash = ref_hash.as_bytes();

        let calc_hash =
            CircuitBuilder::streaming_execute::<_, _, HashOutput>(inputs, 10_000, |ctx, input| {
                blake3_hash(ctx, *input)
            });

        assert_eq!(calc_hash.output_value.value, *ref_hash);
    }

    #[test]
    fn test_blake3_hash_for_finite_len_random_input() {
        let mut byte_arr = [0u8; 32];
        rand::thread_rng().try_fill(&mut byte_arr[..]).unwrap();

        let inputs = InputMessage { byte_arr };
        validate_blake3_hash_for_input(inputs);
    }

    fn validate_against_audited_gadget<const N: usize>(inputs: InputMessage<N>) {
        let opt_hash =
            CircuitBuilder::streaming_execute::<_, _, HashOutput>(inputs, 10_000, |ctx, input| {
                blake3_hash(ctx, *input)
            });
        let audited_hash =
            CircuitBuilder::streaming_execute::<_, _, HashOutput>(inputs, 10_000, |ctx, input| {
                audited::blake3_hash(ctx, *input)
            });

        assert_eq!(opt_hash.output_value.value, audited_hash.output_value.value);
    }

    // The optimized gadget must agree with the audited gadget it replaces
    #[test]
    fn test_matches_audited_gadget() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..4 {
            let mut byte_arr = [0u8; 36];
            rng.fill(&mut byte_arr[..]);
            validate_against_audited_gadget(InputMessage { byte_arr });

            let mut byte_arr = [0u8; 65];
            rng.fill(&mut byte_arr[..]);
            validate_against_audited_gadget(InputMessage { byte_arr });
        }
        validate_against_audited_gadget(InputMessage { byte_arr: [] });
        validate_against_audited_gadget(InputMessage {
            byte_arr: [0xff; CHUNK_LEN],
        });
    }

    #[test]
    fn test_zero_length() {
        let inputs = InputMessage { byte_arr: [] };
        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    fn test_max_length() {
        let inputs = InputMessage {
            byte_arr: [0; CHUNK_LEN],
        };

        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    #[should_panic(
        expected = "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    )]
    fn test_message_too_long() {
        let inputs = InputMessage {
            byte_arr: [0; CHUNK_LEN + 1],
        };

        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    fn test_vectors() {
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestVector>,
        }

        #[derive(Debug, Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors() -> Vec<(Vec<u8>, String)> {
            let path = "src/gadgets/hash/blake3_test_vectors.json";
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);

            let test_vectors: TestVectors = serde_json::from_reader(reader).unwrap();
            test_vectors
                .cases
                .iter()
                .filter(|vector| vector.input_len <= 1024)
                .map(|vector| {
                    let message = (0..251u8).cycle().take(vector.input_len).collect();
                    let expected_hash = String::from_str(&vector.hash[0..64]).unwrap();
                    (message, expected_hash)
                })
                .collect()
        }

        fn validate_blake3_hash_for_input_given_hash<const N: usize>(
            inputs: InputMessage<N>,
            ref_hash: String,
        ) {
            fn bytes_to_hex(bytes: [u8; 32]) -> String {
                bytes.iter().map(|b| format!("{:02x}", b)).collect()
            }

            let calc_hash = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
                inputs,
                10_000,
                |ctx, input| blake3_hash(ctx, *input),
            );

            let calc_hash = bytes_to_hex(calc_hash.output_value.value);

            assert_eq!(calc_hash, ref_hash);
        }

        // Dispatcher: second argument must be an array literal of consts
        macro_rules! dispatch_input {
            ($bytes:expr, $expected_hash:expr, vec![$($n:literal),* $(,)?]) => {{
                match $bytes.len() {
                    $(
                        $n => {
                            let arr: [u8; $n] = $bytes.as_slice().try_into().unwrap();
                            let msg = InputMessage::<$n> { byte_arr: arr };
                            validate_blake3_hash_for_input_given_hash(msg, $expected_hash);
                        }
                    )*
                    _ => { panic!("unexpected length of input") }
                }
            }};
        }

        for (input_bytes, expected_hash) in read_test_vectors() {
            dispatch_input!(
                input_bytes,
                expected_hash,
                vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 63, 64, 65, 127, 128, 129, 1023, 1024
                ]
            );
        }
    }
}

/// Gate cost of the optimized and audited gadgets as garbled, i.e. after g16gen translates every
/// gate into v5 AND/XOR.
#[cfg(test)]
mod gate_cost {
    use std::collections::HashSet;

    use super::{HashOutputWires, InputMessageWires, blake3_hash};
    use crate::{
        CircuitContext, Gate, GateType, WireId,
        circuit::{FromWires, WiresObject, modes::ExecuteMode},
        gadgets::hash::blake3 as audited,
    };

    /// Records emitted gates without evaluating them.
    struct GateRecorder {
        next_wire: usize,
        gates: Vec<Gate>,
    }

    impl CircuitContext for GateRecorder {
        type Mode = ExecuteMode;

        fn issue_wire(&mut self) -> WireId {
            let w = WireId(self.next_wire);
            self.next_wire += 1;
            w
        }

        fn add_gate(&mut self, gate: Gate) {
            self.gates.push(gate);
        }

        fn with_named_child<I: WiresObject, O: FromWires>(
            &mut self,
            _key: [u8; 8],
            inputs: I,
            f: impl Fn(&mut Self, &I) -> O,
            _arity: usize,
        ) -> O {
            f(self, &inputs)
        }
    }

    /// (AND, XOR) gates emitted by g16gen's translation of each source gate type.
    fn v5_cost(gate_type: GateType) -> (u64, u64) {
        match gate_type {
            GateType::And => (1, 0),
            GateType::Xor | GateType::Not => (0, 1),
            GateType::Xnor => (0, 2),
            GateType::Nand | GateType::Nimp | GateType::Ncimp => (1, 1),
            GateType::Or => (1, 2),
            GateType::Nor | GateType::Imp | GateType::Cimp => (1, 3),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Cost {
        /// v5 AND gates, i.e. 16-byte ciphertexts under privacy-free half-gates
        and: u64,
        /// all v5 gates
        total: u64,
        /// gate outputs never read and not part of the hash, which ckt-lvl never frees
        unread: usize,
    }

    /// Signature shared by the optimized and audited gadgets.
    type Hash<const N: usize> = fn(&mut GateRecorder, InputMessageWires<N>) -> HashOutputWires;

    fn cost<const N: usize>(hash: Hash<N>) -> Cost {
        // wires 0 and 1 are the FALSE/TRUE constants
        let mut rec = GateRecorder {
            next_wire: 2,
            gates: Vec::new(),
        };
        let input = InputMessageWires::<N>::new(|| rec.issue_wire());
        let output: HashSet<WireId> = hash(&mut rec, input).to_wires_vec().into_iter().collect();

        let (mut and, mut xor) = (0, 0);
        let mut read = HashSet::new();
        for gate in &rec.gates {
            let (a, x) = v5_cost(gate.gate_type);
            and += a;
            xor += x;
            read.insert(gate.wire_a);
            if gate.gate_type != GateType::Not {
                read.insert(gate.wire_b);
            }
        }
        let unread = rec
            .gates
            .iter()
            .filter(|g| !read.contains(&g.wire_c) && !output.contains(&g.wire_c))
            .count();

        Cost {
            and,
            total: and + xor,
            unread,
        }
    }

    // 36 bytes is the SP1 public-values length hashed by the Groth16 verifier
    // (AND, total, unread) for message lengths 36, 64, 65 and 1024
    #[test]
    fn test_gate_cost() {
        let costs = [
            cost::<36>(blake3_hash),
            cost::<64>(blake3_hash),
            cost::<65>(blake3_hash),
            cost::<1024>(blake3_hash),
        ]
        .map(|c| (c.and, c.total, c.unread));
        let expected = [
            (8762, 50323, 0),
            (10281, 57868, 0),
            (17436, 100013, 0),
            (166431, 939943, 0),
        ];
        assert_eq!(costs, expected);
    }

    // Pins the audited gadget, as the baseline for the optimized gadget above
    #[test]
    fn test_audited_gate_cost() {
        let costs = [
            cost::<36>(audited::blake3_hash),
            cost::<64>(audited::blake3_hash),
            cost::<65>(audited::blake3_hash),
            cost::<1024>(audited::blake3_hash),
        ]
        .map(|c| (c.and, c.total, c.unread));
        let expected = [
            (10848, 61728, 592),
            (10848, 61728, 592),
            (21632, 123264, 1184),
            (172608, 984768, 9472),
        ];
        assert_eq!(costs, expected);
    }
}
