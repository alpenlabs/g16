use std::{
    cmp::Ordering,
    fmt,
    ops::{Add, Div, Mul, Rem, Sub},
};

/// A 24-bit unsigned integer stored in little-endian byte order.
/// Bytes are ordered as [LSB, middle, MSB] for optimal performance on LE systems.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct U24([u8; 3]);

impl U24 {
    pub fn new(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 3] {
        self.0
    }

    pub const MAX: u32 = 0xFFFFFF;

    /// Convert to u32 efficiently using LE layout
    #[inline(always)]
    pub const fn to_u32(self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], 0])
    }

    /// Create from u32 efficiently using LE layout
    #[inline(always)]
    pub const fn from_u32(value: u32) -> Self {
        let bytes = value.to_le_bytes();
        Self([bytes[0], bytes[1], bytes[2]])
    }

    pub fn checked_add(self, rhs: U24) -> Option<U24> {
        let result = self.to_u32().checked_add(rhs.to_u32())?;
        if result > Self::MAX {
            None
        } else {
            Some(Self::from_u32(result))
        }
    }

    pub fn checked_sub(self, rhs: U24) -> Option<U24> {
        let result = self.to_u32().checked_sub(rhs.to_u32())?;
        Some(Self::from_u32(result))
    }

    pub fn checked_mul(self, rhs: U24) -> Option<U24> {
        let result = self.to_u32().checked_mul(rhs.to_u32())?;
        if result > Self::MAX {
            None
        } else {
            Some(Self::from_u32(result))
        }
    }

    pub fn checked_div(self, rhs: U24) -> Option<U24> {
        let result = self.to_u32().checked_div(rhs.to_u32())?;
        Some(Self::from_u32(result))
    }

    pub fn checked_rem(self, rhs: U24) -> Option<U24> {
        let result = self.to_u32().checked_rem(rhs.to_u32())?;
        Some(Self::from_u32(result))
    }
}

impl PartialOrd for U24 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U24 {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare from MSB to LSB for correct ordering
        self.0[2]
            .cmp(&other.0[2])
            .then_with(|| self.0[1].cmp(&other.0[1]))
            .then_with(|| self.0[0].cmp(&other.0[0]))
    }
}

impl fmt::Debug for U24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U24({})", self.to_u32())
    }
}

impl fmt::Display for U24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u32())
    }
}

impl From<U24> for [u8; 3] {
    #[inline]
    fn from(u24: U24) -> Self {
        u24.0
    }
}

impl From<U24> for u32 {
    #[inline]
    fn from(u24: U24) -> Self {
        u24.to_u32()
    }
}

impl From<U24> for u64 {
    #[inline]
    fn from(u24: U24) -> Self {
        u24.to_u32() as u64
    }
}

impl From<U24> for u128 {
    #[inline]
    fn from(u24: U24) -> Self {
        u24.to_u32() as u128
    }
}

impl From<U24> for usize {
    #[inline]
    fn from(u24: U24) -> Self {
        u24.to_u32() as usize
    }
}

impl From<u32> for U24 {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from_u32(value & 0xFFFFFF)
    }
}

impl From<u8> for U24 {
    #[inline]
    fn from(value: u8) -> Self {
        Self([value, 0, 0])
    }
}

impl From<u16> for U24 {
    #[inline]
    fn from(value: u16) -> Self {
        let bytes = value.to_le_bytes();
        Self([bytes[0], bytes[1], 0])
    }
}

impl Add<U24> for U24 {
    type Output = U24;

    #[inline]
    fn add(self, rhs: U24) -> Self::Output {
        Self::from_u32((self.to_u32() + rhs.to_u32()) & 0xFFFFFF)
    }
}

impl Sub<U24> for U24 {
    type Output = U24;

    #[inline]
    fn sub(self, rhs: U24) -> Self::Output {
        Self::from_u32(self.to_u32().wrapping_sub(rhs.to_u32()))
    }
}

impl Mul<U24> for U24 {
    type Output = U24;

    #[inline]
    fn mul(self, rhs: U24) -> Self::Output {
        Self::from_u32((self.to_u32() * rhs.to_u32()) & 0xFFFFFF)
    }
}

impl Div<U24> for U24 {
    type Output = U24;

    #[inline]
    fn div(self, rhs: U24) -> Self::Output {
        Self::from_u32(self.to_u32() / rhs.to_u32())
    }
}

impl Rem<U24> for U24 {
    type Output = U24;

    #[inline]
    fn rem(self, rhs: U24) -> Self::Output {
        Self::from_u32(self.to_u32() % rhs.to_u32())
    }
}
