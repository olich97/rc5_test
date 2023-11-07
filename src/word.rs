use num::{
    traits::{WrappingAdd, WrappingSub},
    Num, NumCast, PrimInt, Zero,
};
use std::{convert::TryInto, mem::size_of};

/// Rappresentation of RC5 word parameter
pub trait Word: Num + Zero + WrappingAdd + WrappingSub + PrimInt + NumCast {
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
    const P: Self = 0xB7E15163;
    const Q: Self = 0x9E3779B9;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        // TODO: handle error?
        Self::from_le_bytes(bytes.try_into().unwrap())
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u32::to_le_bytes(*self).to_vec()
    }
}

impl Word for u64 {
    const P: Self = 0xB7E151628AED2A6B;
    const Q: Self = 0x9E3779B97F4A7C15;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        println!("bytes: {:?}", Self::SIZE_IN_BYTES);
        Self::from_le_bytes(bytes.try_into().unwrap())
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u64::to_le_bytes(*self).to_vec()
    }
}

impl Word for u128 {
    const P: Self = 0xB7E151628AED2A6ABF7158809CF4F3C7;
    const Q: Self = 0x9E3779B97F4A7C15F39CC0605CEDC835;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u128::to_le_bytes(*self).to_vec()
    }
}
