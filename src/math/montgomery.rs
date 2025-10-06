use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut x, mut y) = (BigInt::one(), BigInt::zero());
    let (mut x1, mut y1) = (BigInt::zero(), BigInt::one());
    let (mut a1, mut b1) = (a.clone(), b.clone());

    while !b1.is_zero() {
        let q = &a1 / &b1;

        (x, x1) = (x1.clone(), &x - q.clone() * x1);
        (y, y1) = (y1.clone(), &y - q.clone() * y1);
        (a1, b1) = (b1.clone(), &a1 - q.clone() * b1);
    }

    (a1, x, y)
}

pub fn calculate_montgomery_constants(modulus: BigUint, r: BigUint) -> (BigUint, BigUint) {
    let modulus_signed = modulus.to_bigint().unwrap();
    let r_signed = r.to_bigint().unwrap();

    let (gcd, r_inv_signed, n_inv_signed) = extended_gcd(&r_signed, &modulus_signed);
    assert_eq!(gcd, BigInt::one(), "r and modulus must be coprime");

    let r_inv = ((r_inv_signed % modulus_signed.clone() + modulus_signed.clone())
        % modulus_signed.clone())
    .to_biguint()
    .unwrap();

    let n_prime = ((n_inv_signed % r_signed.clone() + r_signed.clone()) % r_signed.clone())
        .to_biguint()
        .unwrap();

    (r_inv, n_prime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_constants_basic() {
        let modulus = BigUint::from(97u32);
        let r = BigUint::from(128u32);
        let (r_inv, n_p) = calculate_montgomery_constants(modulus.clone(), r.clone());

        assert_eq!(
            (r.clone() * r_inv.clone()) % modulus.clone(),
            BigUint::one()
        );
        assert_eq!((n_p.clone() * modulus.clone()) % r.clone(), BigUint::one());
    }

    #[test]
    fn test_extended_gcd() {
        let a = BigInt::from(48);
        let b = BigInt::from(18);
        let (gcd, x, y) = extended_gcd(&a, &b);

        assert_eq!(gcd, BigInt::from(6));
        assert_eq!(a.clone() * x + b.clone() * y, gcd);
    }
}
