#![no_main]

use arbitrary::Arbitrary;
use ark_ff::{AdditiveGroup, Field};
use ark_std::array;
use g16ckt::{
    Fp254Impl, WireId,
    ark::PrimeField,
    bits_from_biguint_with_len,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, CircuitOutput, EncodeInput, ExecuteMode},
    gadgets::{bigint::BigUint as BigUintOutput, bn254::Fq},
};
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;

// Input struct for Fq tests
struct FqInput<const N: usize> {
    values: [ark_bn254::Fq; N],
}

impl<const N: usize> FqInput<N> {
    fn new(values: [ark_bn254::Fq; N]) -> Self {
        Self { values }
    }
}

impl<const N: usize> CircuitInput for FqInput<N> {
    type WireRepr = [Fq; N];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        array::from_fn(|_| Fq::new(&mut issue))
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.iter().flat_map(|fq| fq.0.iter().copied()).collect()
    }
}

impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for FqInput<N> {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        self.values
            .iter()
            .zip(repr.iter())
            .for_each(|(val, fq_wires)| {
                let bits =
                    bits_from_biguint_with_len(&BigUint::from(val.into_bigint()), Fq::N_BITS)
                        .unwrap();
                fq_wires.0.iter().zip(bits).for_each(|(w, b)| {
                    cache.feed_wire(*w, b);
                });
            });
    }
}

// Output struct for Fq tests
struct FqOutput {
    value: ark_bn254::Fq,
}

impl CircuitOutput<ExecuteMode> for FqOutput {
    type WireRepr = Fq;

    fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
        // Decode BigIntWires to BigUint, then convert to ark_bn254::Fq
        let biguint = BigUintOutput::decode(wires.0, cache);
        let value = ark_bn254::Fq::from(biguint);
        Self { value }
    }
}

const FQ_LEN: usize = 254;

#[derive(Debug, Arbitrary)]
struct BinaryOps {
    a: [u8; FQ_LEN],
    b: [u8; FQ_LEN],
}

fuzz_target!(|ops: BinaryOps| {
    let a_uint = ark_bn254::Fq::from_le_bytes_mod_order(&ops.a);
    let b_uint = ark_bn254::Fq::from_le_bytes_mod_order(&ops.b);
    let a_mont = Fq::as_montgomery(a_uint);
    let b_mont = Fq::as_montgomery(b_uint);

    // multiplication c = a * b
    let c_uint = a_uint * b_uint;
    let c_mont = Fq::as_montgomery(c_uint);
    let input = FqInput::new([a_mont, b_mont]);
    let result =
        CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
            let [a, b] = input;
            Fq::mul_montgomery(ctx, a, b)
        });
    assert_eq!(result.output_value.value, c_mont);

    // multiplication by constant c = a * k
    let c_uint = a_uint * b_uint;
    let c_mont = Fq::as_montgomery(c_uint);
    let input = FqInput::new([a_mont]);
    let result =
        CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
            let [a] = input;
            Fq::mul_by_constant_montgomery(ctx, a, &b_mont)
        });
    assert_eq!(result.output_value.value, c_mont);

    // square c = a * a
    let c_uint = a_uint * a_uint;
    let c_mont = Fq::as_montgomery(c_uint);
    let input = FqInput::new([a_mont]);
    let result =
        CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
            let [a] = input;
            Fq::square_montgomery(ctx, a)
        });
    assert_eq!(result.output_value.value, c_mont);

    // c = a^(-1)
    if a_uint != ark_bn254::Fq::ZERO {
        let c_uint = a_uint.inverse().unwrap();
        let c_mont = Fq::as_montgomery(c_uint);
        let input = FqInput::new([a_mont]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq::inverse_montgomery(ctx, a)
            });
        assert_eq!(result.output_value.value, c_mont);
    }
});
