use num::{
    traits::{WrappingAdd, WrappingSub},
    Num, NumCast, PrimInt, Zero,
};
use std::{convert::TryInto, mem::size_of};

/// Rappresentation of RC5 word parameter
pub trait Word: Num + Zero + WrappingAdd + WrappingSub + PrimInt + NumCast {
    // magic costants
    const P: Self; // Odd((e − 2)2^w)
    const Q: Self; // Odd((φ − 1)2^w)
    // Byte size for the type, usefull for block separation of inputtext
    const SIZE_IN_BYTES: usize = size_of::<Self>();
    /// Actual w parameter, word size in bits: e.g 16, 32, 64, 128, 256
    const SIZE_IN_BITS: usize = Self::SIZE_IN_BYTES * 8;

    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn to_le_bytes(&self) -> Vec<u8>;
}

impl Word for u32 {
    const P: Self = 0xb7e15163;
    const Q: Self = 0x9e3779b9;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        // TODO: handle error
        Self::from_le_bytes(bytes.try_into().unwrap())
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u32::to_le_bytes(*self).to_vec()
    }
}
