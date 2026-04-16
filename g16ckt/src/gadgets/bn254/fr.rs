//! BN254 Scalar Field Fr Implementation
//!
//! This module provides circuit-based operations on the BN254 scalar field Fr.
//! The scalar field Fr is used for exponents in elliptic curve operations and
//! has the modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!
//! The Fr type wraps BigIntWires to provide field-specific operations in Montgomery form
//! for efficient modular arithmetic within garbled circuits.

use std::ops::{Deref, DerefMut};

use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::{
    CircuitContext, WireId,
    circuit::WiresObject,
    gadgets::{
        self,
        bigint::{BigIntWires, Error},
    },
};

/// BN254 scalar field Fr implementation
///
/// Represents elements in the scalar field Fr of the BN254 elliptic curve.
/// This is the field used for private keys and exponents in BN254 operations.
#[derive(Clone, Debug)]
pub struct Fr(pub BigIntWires);

impl Deref for Fr {
    type Target = BigIntWires;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Fr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WiresObject for Fr {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.iter().copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self(self.0.clone_from(wire_gen))
    }
}

impl crate::circuit::FromWires for Fr {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() == Fr::N_BITS {
            Some(Self(crate::gadgets::bigint::BigIntWires::from_bits(
                wires.iter().copied(),
            )))
        } else {
            None
        }
    }
}

impl Fr {
    pub const N_BITS: usize = 254;

    /// Create constant field element wires from a known value
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add wires to
    /// * `u` - Field element value to encode as constant
    ///
    /// # Returns
    /// Field element wires representing the constant value
    pub fn new_constant(u: &ark_bn254::Fr) -> Result<Fr, Error> {
        Ok(Fr(BigIntWires::new_constant(
            Self::N_BITS,
            &BigUint::from(u.into_bigint()),
        )?))
    }

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Fr {
        Fr(BigIntWires::from_ctx(circuit, Self::N_BITS))
    }

    pub fn new(issue: impl FnMut() -> WireId) -> Fr {
        Fr(BigIntWires::new(issue, Self::N_BITS))
    }

    pub fn get_wire_bits_fn(
        wires: &Fr,
        value: &ark_bn254::Fr,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires
            .0
            .get_wire_bits_fn(&BigUint::from(value.into_bigint()))
    }

    /// Convert field element wires to a bitmask string for debugging
    ///
    /// # Arguments
    /// * `wires` - The field element wires
    /// * `get_val` - Function to get the boolean value of a wire
    ///
    /// # Returns
    /// String representation of the field element as bits
    pub fn to_bitmask(wires: &Fr, get_val: impl Fn(WireId) -> bool) -> String {
        wires.0.to_bitmask(&get_val)
    }

    pub fn to_bits(u: ark_bn254::Fr) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fr {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fr::from(u)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use rand::Rng;

    use super::*;
    use crate::test_utils::trng;

    fn rnd() -> ark_bn254::Fr {
        loop {
            if let Some(bn) = ark_bn254::Fr::from_random_bytes(&trng().r#gen::<[u8; 32]>()) {
                return bn;
            }
        }
    }

    #[test]
    fn test_fr_random() {
        let u = rnd();
        println!("u: {u:?}");
        let b = Fr::to_bits(u);
        let v = Fr::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }
}
