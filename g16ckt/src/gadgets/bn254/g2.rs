use std::collections::HashMap;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use circuit_component_macro::component;
use num_bigint::BigUint;

use crate::{
    CircuitContext, WireId,
    circuit::{FromWires, TRUE_WIRE, WiresArity, WiresObject},
    gadgets::{
        bigint::{self, BigIntWires, Error},
        bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2},
    },
};

#[derive(Clone, Debug)]
pub struct G2Projective {
    pub x: Fq2,
    pub y: Fq2,
    pub z: Fq2,
}

impl WiresObject for G2Projective {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.x.to_wires_vec());
        wires.extend(self.y.to_wires_vec());
        wires.extend(self.z.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        let Self { x, y, z } = self;

        Self {
            x: x.clone_from(wire_gen),
            y: y.clone_from(wire_gen),
            z: z.clone_from(wire_gen),
        }
    }
}

impl FromWires for G2Projective {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() == G2Projective::N_BITS {
            let len = wires.len() / 3;
            let mut chunks = wires.chunks(len);
            Some(Self {
                x: Fq2::from_wires(chunks.next()?)?,
                y: Fq2::from_wires(chunks.next()?)?,
                z: Fq2::from_wires(chunks.next()?)?,
            })
        } else {
            None
        }
    }
}

impl G2Projective {
    pub const N_BITS: usize = 3 * Fq2::N_BITS;

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Self {
        Self {
            x: Fq2::from_ctx(circuit),
            y: Fq2::from_ctx(circuit),
            z: Fq2::from_ctx(circuit),
        }
    }

    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        Self {
            x: Fq2::new(&mut issue),
            y: Fq2::new(&mut issue),
            z: Fq2::new(issue),
        }
    }

    pub fn new_constant(u: &ark_bn254::G2Projective) -> Result<Self, Error> {
        Ok(Self {
            x: Fq2::from_components(
                Fq::new_constant(&u.x.c0).unwrap(),
                Fq::new_constant(&u.x.c1).unwrap(),
            ),
            y: Fq2::from_components(
                Fq::new_constant(&u.y.c0).unwrap(),
                Fq::new_constant(&u.y.c1).unwrap(),
            ),
            z: Fq2::from_components(
                Fq::new_constant(&u.z.c0).unwrap(),
                Fq::new_constant(&u.z.c1).unwrap(),
            ),
        })
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G2Projective {
        let bits1_c0 = bits[0..Fq::N_BITS].to_vec();
        let bits1_c1 = bits[Fq::N_BITS..Fq2::N_BITS].to_vec();
        let bits2_c0 = bits[Fq2::N_BITS..Fq2::N_BITS + Fq::N_BITS].to_vec();
        let bits2_c1 = bits[Fq2::N_BITS + Fq::N_BITS..Fq2::N_BITS * 2].to_vec();
        let bits3_c0 = bits[Fq2::N_BITS * 2..Fq2::N_BITS * 2 + Fq::N_BITS].to_vec();
        let bits3_c1 = bits[Fq2::N_BITS * 2 + Fq::N_BITS..Fq2::N_BITS * 3].to_vec();
        ark_bn254::G2Projective {
            x: Fq2::from_bits((bits1_c0, bits1_c1)),
            y: Fq2::from_bits((bits2_c0, bits2_c1)),
            z: Fq2::from_bits((bits3_c0, bits3_c1)),
        }
    }

    pub fn to_bitmask(&self, get_val: impl Fn(WireId) -> bool) -> String {
        let to_char = |wire_id: &WireId| if (get_val)(*wire_id) { '1' } else { '0' };
        let x = self
            .x
            .c0()
            .iter()
            .chain(self.x.c1().iter())
            .map(to_char)
            .collect::<String>();
        let y = self
            .y
            .c0()
            .iter()
            .chain(self.y.c1().iter())
            .map(to_char)
            .collect::<String>();
        let z = self
            .z
            .c0()
            .iter()
            .chain(self.z.c1().iter())
            .map(to_char)
            .collect::<String>();

        format!("x: {x}, y: {y}, z: {z}")
    }

    pub fn to_bitvec(&self, get_val: impl Fn(WireId) -> bool) -> Vec<bool> {
        let to_char = |wire_id: &WireId| (get_val)(*wire_id);
        let x = self
            .x
            .c0()
            .iter()
            .chain(self.x.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();
        let y = self
            .y
            .c0()
            .iter()
            .chain(self.y.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();
        let z = self
            .z
            .c0()
            .iter()
            .chain(self.z.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();

        let mut v = Vec::new();
        v.extend(x);
        v.extend(y);
        v.extend(z);

        v
    }

    pub fn as_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::as_montgomery(p.x),
            y: Fq2::as_montgomery(p.y),
            z: Fq2::as_montgomery(p.z),
        }
    }

    pub fn from_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::from_montgomery(p.x),
            y: Fq2::from_montgomery(p.y),
            z: Fq2::from_montgomery(p.z),
        }
    }

    pub fn get_wire_bits_fn(
        wires: &G2Projective,
        value: &ark_bn254::G2Projective,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let G2Projective {
            x: wires_x,
            y: wires_y,
            z: wires_z,
        } = wires;
        let (x_c0, x_c1) = Fq2::to_bits(value.x);
        let (y_c0, y_c1) = Fq2::to_bits(value.y);
        let (z_c0, z_c1) = Fq2::to_bits(value.z);

        let bits = wires_x
            .c0()
            .iter()
            .zip(x_c0.iter())
            .chain(wires_x.c1().iter().zip(x_c1.iter()))
            .chain(wires_y.c0().iter().zip(y_c0.iter()))
            .chain(wires_y.c1().iter().zip(y_c1.iter()))
            .chain(wires_z.c0().iter().zip(z_c0.iter()))
            .chain(wires_z.c1().iter().zip(z_c1.iter()))
            .map(|(wire_id, value)| (*wire_id, *value))
            .collect::<HashMap<WireId, bool>>();

        Ok(move |wire_id: WireId| bits.get(&wire_id).copied())
    }
}

impl G2Projective {
    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    #[component]
    pub fn add_montgomery<C: CircuitContext>(
        circuit: &mut C,
        p: &G2Projective,
        q: &G2Projective,
    ) -> G2Projective {
        assert_eq!(p.x.c0().len() + p.x.c1().len(), Fq2::N_BITS);
        assert_eq!(p.y.c0().len() + p.y.c1().len(), Fq2::N_BITS);
        assert_eq!(p.z.c0().len() + p.z.c1().len(), Fq2::N_BITS);

        assert_eq!(q.x.c0().len() + q.x.c1().len(), Fq2::N_BITS);
        assert_eq!(q.y.c0().len() + q.y.c1().len(), Fq2::N_BITS);
        assert_eq!(q.z.c0().len() + q.z.c1().len(), Fq2::N_BITS);

        let G2Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;
        let G2Projective {
            x: x2,
            y: y2,
            z: z2,
        } = q;

        let z1s = Fq2::square_montgomery(circuit, z1);
        let z2s = Fq2::square_montgomery(circuit, z2);
        let z1c = Fq2::mul_montgomery(circuit, &z1s, z1);
        let z2c = Fq2::mul_montgomery(circuit, &z2s, z2);
        let u1 = Fq2::mul_montgomery(circuit, x1, &z2s);
        let u2 = Fq2::mul_montgomery(circuit, x2, &z1s);
        let s1 = Fq2::mul_montgomery(circuit, y1, &z2c);
        let s2 = Fq2::mul_montgomery(circuit, y2, &z1c);
        let r = Fq2::sub(circuit, &s1, &s2);
        let h = Fq2::sub(circuit, &u1, &u2);
        let h2 = Fq2::square_montgomery(circuit, &h);
        let g = Fq2::mul_montgomery(circuit, &h, &h2);
        let v = Fq2::mul_montgomery(circuit, &u1, &h2);
        let r2 = Fq2::square_montgomery(circuit, &r);
        let r2g = Fq2::add(circuit, &r2, &g);
        let vd = Fq2::double(circuit, &v);
        let x3 = Fq2::sub(circuit, &r2g, &vd);
        let vx3 = Fq2::sub(circuit, &v, &x3);
        let w = Fq2::mul_montgomery(circuit, &r, &vx3);
        let s1g = Fq2::mul_montgomery(circuit, &s1, &g);
        let y3 = Fq2::sub(circuit, &w, &s1g);
        let z1z2 = Fq2::mul_montgomery(circuit, z1, z2);
        let z3 = Fq2::mul_montgomery(circuit, &z1z2, &h);

        let z1_0 = Fq2::equal_constant(circuit, z1, &ark_bn254::Fq2::zero());
        let z2_0 = Fq2::equal_constant(circuit, z2, &ark_bn254::Fq2::zero());

        let zero = Fq2::from_components(
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
        );

        let s = [z1_0, z2_0];

        // Implement multiplexer for Fq2 by multiplexing each component
        let x_c0 = Fq::multiplexer(
            circuit,
            &[
                x3.c0().clone(),
                x2.c0().clone(),
                x1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let x_c1 = Fq::multiplexer(
            circuit,
            &[
                x3.c1().clone(),
                x2.c1().clone(),
                x1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let x = Fq2::from_components(x_c0, x_c1);

        let y_c0 = Fq::multiplexer(
            circuit,
            &[
                y3.c0().clone(),
                y2.c0().clone(),
                y1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let y_c1 = Fq::multiplexer(
            circuit,
            &[
                y3.c1().clone(),
                y2.c1().clone(),
                y1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let y = Fq2::from_components(y_c0, y_c1);

        let z_c0 = Fq::multiplexer(
            circuit,
            &[
                z3.c0().clone(),
                z2.c0().clone(),
                z1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let z_c1 = Fq::multiplexer(
            circuit,
            &[
                z3.c1().clone(),
                z2.c1().clone(),
                z1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let z = Fq2::from_components(z_c0, z_c1);

        G2Projective { x, y, z }
    }

    #[component]
    pub fn double_montgomery<C: CircuitContext>(circuit: &mut C, p: &G2Projective) -> G2Projective {
        assert_eq!(p.x.c0().len() + p.x.c1().len(), Fq2::N_BITS);
        assert_eq!(p.y.c0().len() + p.y.c1().len(), Fq2::N_BITS);
        assert_eq!(p.z.c0().len() + p.z.c1().len(), Fq2::N_BITS);

        let G2Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;

        let x2 = Fq2::square_montgomery(circuit, x1);
        let y2 = Fq2::square_montgomery(circuit, y1);
        let m = Fq2::triple(circuit, &x2);
        let t = Fq2::square_montgomery(circuit, &y2);
        let xy2 = Fq2::mul_montgomery(circuit, x1, &y2);
        let xy2d = Fq2::double(circuit, &xy2);
        let s = Fq2::double(circuit, &xy2d);
        let m2 = Fq2::square_montgomery(circuit, &m);
        let sd = Fq2::double(circuit, &s);
        let xr = Fq2::sub(circuit, &m2, &sd);
        let sxr = Fq2::sub(circuit, &s, &xr);
        let msxr = Fq2::mul_montgomery(circuit, &m, &sxr);
        let td = Fq2::double(circuit, &t);
        let tdd = Fq2::double(circuit, &td);
        let tddd = Fq2::double(circuit, &tdd);
        let yr = Fq2::sub(circuit, &msxr, &tddd);
        let yz = Fq2::mul_montgomery(circuit, y1, z1);
        let zr = Fq2::double(circuit, &yz);

        let z_0 = Fq2::equal_constant(circuit, z1, &ark_bn254::Fq2::zero());
        let zero = Fq2::from_components(
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
        );
        let z_c0 = Fq::multiplexer(circuit, &[zr.c0().clone(), zero.c0().clone()], &[z_0], 1);
        let z_c1 = Fq::multiplexer(circuit, &[zr.c1().clone(), zero.c1().clone()], &[z_0], 1);
        let z = Fq2::from_components(z_c0, z_c1);

        G2Projective { x: xr, y: yr, z }
    }

    #[component(offcircuit_args = "w")]
    pub fn multiplexer<C: CircuitContext>(
        circuit: &mut C,
        a: &[G2Projective],
        s: &[WireId],
        w: usize,
    ) -> G2Projective {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        assert_eq!(s.len(), w);

        // Multiplexer for G2 by component-wise selection
        let x_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.x.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let x_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.x.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let y_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.y.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let y_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.y.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let z_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.z.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let z_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.z.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        G2Projective {
            x: Fq2::from_components(x_c0, x_c1),
            y: Fq2::from_components(y_c0, y_c1),
            z: Fq2::from_components(z_c0, z_c1),
        }
    }

    #[component]
    pub fn neg<C: CircuitContext>(circuit: &mut C, p: &G2Projective) -> G2Projective {
        G2Projective {
            x: p.x.clone(),
            y: Fq2::neg(circuit, &p.y),
            z: p.z.clone(),
        }
    }

    /// check whether or not the point is on the curve or not
    /// checks y^2=x^3+Bz^6 (Jacobian projective coordinates)
    #[component]
    pub fn is_on_curve<C: CircuitContext>(circuit: &mut C, p: &G2Projective) -> WireId {
        let x2 = Fq2::square_montgomery(circuit, &p.x);
        let x3 = Fq2::mul_montgomery(circuit, &p.x, &x2);
        let y2 = Fq2::square_montgomery(circuit, &p.y);
        let z2 = Fq2::square_montgomery(circuit, &p.z);
        let z4 = Fq2::square_montgomery(circuit, &z2);
        let z6 = Fq2::mul_montgomery(circuit, &z2, &z4);
        let b_z6 = Fq2::mul_by_constant_montgomery(
            circuit,
            &z6,
            &Fq2::as_montgomery(ark_bn254::g2::Config::COEFF_B),
        );
        let temp = Fq2::add(circuit, &x3, &b_z6);
        let should_be_zero = Fq2::sub(circuit, &y2, &temp);
        {
            let c0 = bigint::equal_zero(circuit, should_be_zero.c0());
            let c1 = bigint::equal_zero(circuit, should_be_zero.c1());
            let is_zero = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: c0,
                wire_b: c1,
                wire_c: is_zero,
                gate_type: crate::GateType::And,
            });
            is_zero
        }
    }

    /// Deserialize into G2Projective from its 64 byte serialized bit representation.
    // Follows arkworks implementation here:
    // https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/models/short_weierstrass/mod.rs#L145
    pub fn deserialize_checked<C: CircuitContext>(
        circuit: &mut C,
        serialized_bits: [WireId; 64 * 8],
    ) -> DecompressedG2Wires {
        let (x, is_x_valid, flag) = {
            let (num1, num2, flag) = (
                &serialized_bits[0..Fq::N_BITS],
                &serialized_bits[32 * 8..32 * 8 + Fq::N_BITS],
                &serialized_bits[32 * 8 + Fq::N_BITS..],
            );
            let a0 = BigIntWires {
                bits: num1.to_vec(),
            };
            let a1 = BigIntWires {
                bits: num2.to_vec(),
            };
            let r: BigUint = ark_bn254::Fq::MODULUS.into();
            let valid_fq = {
                let valid_a0 = bigint::less_than_constant(circuit, &a0, &r);
                let valid_a1 = bigint::less_than_constant(circuit, &a1, &r);
                let valid_fq = circuit.issue_wire();
                circuit.add_gate(crate::Gate {
                    wire_a: valid_a0,
                    wire_b: valid_a1,
                    wire_c: valid_fq,
                    gate_type: crate::GateType::And,
                });
                valid_fq
            };

            // convert input field element in standard form into montgomery form
            let r = Fq::as_montgomery(ark_bn254::Fq::ONE);
            let a_mont_x = Fq::mul_by_constant_montgomery(circuit, &Fq(a0), &r.square());
            let r = Fq::as_montgomery(ark_bn254::Fq::ONE);
            let a_mont_y = Fq::mul_by_constant_montgomery(circuit, &Fq(a1), &r.square());

            // flag_0 is lsb, flag 1 is msb
            (Fq2([a_mont_x, a_mont_y]), valid_fq, [flag[0], flag[1]])
        };

        // Part 1: Extract Flags

        let is_y_positive = {
            // In arkworks, given:
            // const Y_IS_POSITIVE: u8 = 0;
            let flag_or = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: flag[0],
                wire_b: flag[1],
                wire_c: flag_or,
                gate_type: crate::GateType::Or,
            });
            let flag_nor = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: flag_or,
                wire_b: TRUE_WIRE,
                wire_c: flag_nor,
                gate_type: crate::GateType::Xor,
            });
            flag_nor
        };

        let is_y_negative = {
            // In arkworks, given:
            // const Y_IS_NEGATIVE: u8 = 1 << 7;
            let tmp0 = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: flag[0],
                wire_b: TRUE_WIRE,
                wire_c: tmp0,
                gate_type: crate::GateType::Xor,
            });
            let tmp1 = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: flag[1],
                wire_b: tmp0,
                wire_c: tmp1,
                gate_type: crate::GateType::And,
            });
            tmp1
        };

        // rest of the flags (11 and 01) represent identity and None, so are invalid flags
        let flags_is_valid = {
            let tmp0 = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: is_y_positive,
                wire_b: is_y_negative,
                wire_c: tmp0,
                gate_type: crate::GateType::Or,
            });
            tmp0
        };

        // Part 2: compute (X, Y, Z)

        let x2 = Fq2::square_montgomery(circuit, &x);
        let x3 = Fq2::mul_montgomery(circuit, &x2, &x);
        let y2 = Fq2::add_constant(
            circuit,
            &x3,
            &Fq2::as_montgomery(ark_bn254::g2::Config::COEFF_B),
        );

        let y = Fq2::sqrt_general_montgomery(circuit, &y2);
        let rhs_is_qr = {
            // check if y * y == y2 to ensure rhs was a quadratic residue to begin with,
            // if it was not, then it means (x,y) is not a point on the curve
            let y_y = Fq2::square_montgomery(circuit, &y);

            let match_c0 = bigint::equal(circuit, y2.c0(), y_y.c0());
            let match_c1 = bigint::equal(circuit, y2.c1(), y_y.c1());
            let match_c0_and_c1 = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: match_c0,
                wire_b: match_c1,
                wire_c: match_c0_and_c1,
                gate_type: crate::GateType::And,
            });
            match_c0_and_c1
        };

        // analogous to get_point_from_x_unchecked
        let neg_y = Fq2::neg(circuit, &y);
        let y_neg_greater = Fq2::greater_than(circuit, &neg_y, &y);
        let tsy = {
            let tsy_c0 = bigint::select(circuit, y.c0(), neg_y.c0(), y_neg_greater);
            let tsy_c1 = bigint::select(circuit, y.c1(), neg_y.c1(), y_neg_greater);
            Fq2([Fq(tsy_c0), Fq(tsy_c1)])
        };
        let tsy_neg = {
            let tsy_neg_c0 = bigint::select(circuit, neg_y.c0(), y.c0(), y_neg_greater);
            let tsy_neg_c1 = bigint::select(circuit, neg_y.c1(), y.c1(), y_neg_greater);
            Fq2([Fq(tsy_neg_c0), Fq(tsy_neg_c1)])
        };

        let final_y_0 = bigint::select(circuit, tsy_neg.c0(), tsy.c0(), is_y_negative);
        let final_y_1 = bigint::select(circuit, tsy_neg.c1(), tsy.c1(), is_y_negative);

        // z = 1 in Montgomery
        let one_m = Fq::as_montgomery(ark_bn254::Fq::ONE);
        let zero_m = Fq::as_montgomery(ark_bn254::Fq::ZERO);

        let input_is_valid = {
            // Input is invalid if input is not a valid point in the curve or deserialization error
            // valid only if both crieterion is met
            let tmp0 = circuit.issue_wire();
            let tmp1 = circuit.issue_wire();
            circuit.add_gate(crate::Gate {
                wire_a: rhs_is_qr,
                wire_b: flags_is_valid,
                wire_c: tmp0,
                gate_type: crate::GateType::And,
            });
            circuit.add_gate(crate::Gate {
                wire_a: tmp0,
                wire_b: is_x_valid,
                wire_c: tmp1,
                gate_type: crate::GateType::And,
            });
            tmp1
        };

        DecompressedG2Wires {
            point: G2Projective {
                x: x.clone(),
                y: Fq2([Fq(final_y_0), Fq(final_y_1)]),
                // In Fq2, ONE is (c0=1, c1=0). Use Montgomery representation.
                z: Fq2([
                    Fq::new_constant(&one_m).unwrap(),
                    Fq::new_constant(&zero_m).unwrap(),
                ]),
            },
            is_valid: input_is_valid,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompressedG2Wires {
    pub p: Fq2,
    pub y_flag: WireId,
}

impl CompressedG2Wires {
    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        Self {
            p: Fq2::new(&mut issue),
            y_flag: issue(),
        }
    }
}

impl WiresObject for CompressedG2Wires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let Self { p, y_flag } = self;

        let mut v = p.to_wires_vec();
        v.push(*y_flag);
        v
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self {
            p: self.p.clone_from(wire_gen),
            y_flag: self.y_flag.clone_from(wire_gen),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecompressedG2Wires {
    pub point: G2Projective,
    pub is_valid: WireId,
}

impl WiresObject for DecompressedG2Wires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.point.to_wires_vec());
        wires.push(self.is_valid);
        wires
    }

    fn clone_from(&self, mut wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self {
            point: self.point.clone_from(&mut wire_gen),
            is_valid: wire_gen(),
        }
    }
}

impl FromWires for DecompressedG2Wires {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        assert_eq!(wires.len(), DecompressedG2Wires::ARITY);
        Some(Self {
            point: G2Projective::from_wires(&wires[0..G2Projective::N_BITS])?,
            is_valid: wires[G2Projective::N_BITS],
        })
    }
}

impl WiresArity for DecompressedG2Wires {
    const ARITY: usize = G2Projective::N_BITS + 1;
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use rand::{Rng, thread_rng};

    use super::*;
    use crate::{
        circuit::{CircuitBuilder, CircuitInput, EncodeInput, modes::CircuitMode},
        gadgets::bn254::pairing::double_in_place,
        test_utils::trng,
    };

    pub fn rnd_g2(rng: &mut impl Rng) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective::rand(rng)
    }

    // Standardized input/output structures for G2 tests
    pub struct G2Input<const N: usize> {
        pub points: [ark_bn254::G2Projective; N],
    }

    pub struct G2InputWire<const N: usize> {
        pub points: [G2Projective; N],
    }

    impl<const N: usize> CircuitInput for G2Input<N> {
        type WireRepr = G2InputWire<N>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            G2InputWire {
                points: std::array::from_fn(|_| G2Projective::new(&mut issue)),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            let mut wires = Vec::new();
            for point in &repr.points {
                wires.extend(point.to_wires_vec());
            }
            wires
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for G2Input<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            for (point_wire, point_val) in repr.points.iter().zip(self.points.iter()) {
                let point_fn = G2Projective::get_wire_bits_fn(point_wire, point_val).unwrap();
                for &wire_id in point_wire
                    .x
                    .c0()
                    .iter()
                    .chain(point_wire.x.c1().iter())
                    .chain(point_wire.y.c0().iter())
                    .chain(point_wire.y.c1().iter())
                    .chain(point_wire.z.c0().iter())
                    .chain(point_wire.z.c1().iter())
                {
                    if let Some(bit) = point_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }
    }

    #[test]
    fn test_g2p_add_montgomery() {
        // Generate random G2 points
        let mut rng = thread_rng();
        let a = rnd_g2(&mut rng);
        let b = rnd_g2(&mut rng);
        let c = a + b;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let b_mont = G2Projective::as_montgomery(b);
        let c_mont = G2Projective::as_montgomery(c);

        let inputs = G2Input {
            points: [a_mont, b_mont],
        };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::add_montgomery(
                    root,
                    &inputs_wire.points[0],
                    &inputs_wire.points[1],
                );
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, c_mont);
    }

    #[test]
    fn test_g2p_double_montgomery() {
        // Generate random G2 point
        let mut rng = thread_rng();
        let a = rnd_g2(&mut rng);
        let c = a + a;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let c_mont = G2Projective::as_montgomery(c);

        let inputs = G2Input { points: [a_mont] };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::double_montgomery(root, &inputs_wire.points[0]);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, c_mont);
    }

    #[test]
    fn test_double_in_place() {
        use ark_ec::CurveGroup;

        // a is in Jacobian
        let mut rng = thread_rng();
        let a = rnd_g2(&mut rng);

        // Jacobian doubling via library, then to affine
        let b_aff = (a + a).into_affine();

        // Start from affine (x,y,1) but run HOMOGENEOUS doubling
        let a_aff = a.into_affine();
        let mut r = ark_bn254::G2Projective::new(a_aff.x, a_aff.y, ark_bn254::Fq2::ONE);
        double_in_place(&mut r); // r = (X,Y,Z) in HOMOGENEOUS

        // Convert HOMOGENEOUS -> JACOBIAN expected by arkworks:
        r.x *= r.z; // X' = X*Z
        let z2 = r.z.square();
        r.y *= z2; // Y' = Y*Z^2
        // Z' = Z

        let r_aff = r.into_affine(); // now safe to normalize
        assert_eq!(b_aff, r_aff);
    }

    #[test]
    fn test_g2p_neg() {
        // Generate random G2 point
        let a = rnd_g2(&mut trng());
        let neg_a = -a;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let neg_a_mont = G2Projective::as_montgomery(neg_a);

        let inputs = G2Input { points: [a_mont] };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::neg(root, &inputs_wire.points[0]);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, neg_a_mont);
    }

    #[test]
    fn test_g2p_multiplexer() {
        let w = 2;
        let n = 2_usize.pow(w as u32);
        let a_val = (0..n)
            .map(|_| G2Projective::as_montgomery(rnd_g2(&mut trng())))
            .collect::<Vec<_>>();
        let s_val = (0..w).map(|_| trng().r#gen()).collect::<Vec<_>>();

        let mut u = 0;
        for i in s_val.iter().rev() {
            u = u + u + if *i { 1 } else { 0 };
        }
        let expected = a_val[u];

        // Define input structure
        struct MultiplexerInputs {
            a: Vec<ark_bn254::G2Projective>,
            s: Vec<bool>,
        }
        struct MultiplexerInputsWire {
            a: Vec<G2Projective>,
            s: Vec<WireId>,
        }
        impl crate::circuit::CircuitInput for MultiplexerInputs {
            type WireRepr = MultiplexerInputsWire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MultiplexerInputsWire {
                    a: (0..self.a.len())
                        .map(|_| G2Projective::new(&mut issue))
                        .collect(),
                    s: (0..self.s.len()).map(|_| (issue)()).collect(),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                for g2 in &repr.a {
                    wires.extend(g2.to_wires_vec());
                }
                wires.extend(&repr.s);
                wires
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MultiplexerInputs {
            fn encode(&self, repr: &MultiplexerInputsWire, cache: &mut M) {
                for (g2_wire, g2_val) in repr.a.iter().zip(self.a.iter()) {
                    let g2_fn = G2Projective::get_wire_bits_fn(g2_wire, g2_val).unwrap();
                    for &wire_id in g2_wire
                        .x
                        .c0()
                        .iter()
                        .chain(g2_wire.x.c1().iter())
                        .chain(g2_wire.y.c0().iter())
                        .chain(g2_wire.y.c1().iter())
                        .chain(g2_wire.z.c0().iter())
                        .chain(g2_wire.z.c1().iter())
                    {
                        if let Some(bit) = g2_fn(wire_id) {
                            cache.feed_wire(wire_id, bit);
                        }
                    }
                }
                for (&wire_id, &bit) in repr.s.iter().zip(self.s.iter()) {
                    cache.feed_wire(wire_id, bit);
                }
            }
        }

        let inputs = MultiplexerInputs { a: a_val, s: s_val };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires =
                    G2Projective::multiplexer(root, &inputs_wire.a, &inputs_wire.s, w);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, expected);
    }
}
