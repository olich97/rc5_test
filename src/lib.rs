pub mod word;
use std::{
    cmp::max,
    convert::{TryFrom, TryInto},
};

use num::{traits::FromBytes, Zero};
use word::Word;

const ROUNDS: u8 = 12;
/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode<W: Word>(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    let extended_key_table = expand_key::<W>(key, ROUNDS);
    // init A and B
    let mut a = W::from_le_bytes(plaintext[..W::SIZE_IN_BYTES].try_into().unwrap())
        .wrapping_add(&extended_key_table[0]);
    let mut b = W::from_le_bytes(plaintext[W::SIZE_IN_BYTES..].try_into().unwrap())
        .wrapping_add(&extended_key_table[1]);

    for i in 1..=ROUNDS.into() {
        a = (a ^ b)
            .rotate_left(b.to_u32().unwrap())
            .wrapping_add(&extended_key_table[2 * i]);
        b = (b ^ a)
            .rotate_left(a.to_u32().unwrap())
            .wrapping_add(&extended_key_table[2 * i + 1]);
    }

    let mut ciphertext = Vec::from(W::to_le_bytes(&a)); //a.to_le_bytes().as_ref());
    ciphertext.extend_from_slice(&W::to_le_bytes(&b));
    ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode<W: Word>(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let extended_key_table = expand_key::<W>(key, ROUNDS);

    let mut a = W::from_le_bytes(&ciphertext[..W::SIZE_IN_BYTES]);
    let mut b = W::from_le_bytes(&ciphertext[W::SIZE_IN_BYTES..]);

    for i in (1..=ROUNDS.into()).rev() {
        b = b
            .wrapping_sub(&extended_key_table[2 * i + 1])
            .rotate_right(a.to_u32().unwrap()) // not sure if works
            ^ a;
        a = a
            .wrapping_sub(&extended_key_table[2 * i])
            .rotate_right(b.to_u32().unwrap())
            ^ b;
    }

    a = a.wrapping_sub(&extended_key_table[0]);
    b = b.wrapping_sub(&extended_key_table[1]);

    let mut plaintext = Vec::from(W::to_le_bytes(&a)); // a.to_le_bytes().as_ref());
    plaintext.extend_from_slice(&W::to_le_bytes(&b));
    plaintext
}

/*
 * The key-expansion routine: expands the user's secret key K to fill the expanded key array S
 * so that S resembles an array of t = 2(r+1) random binary words defined by K
 */
fn expand_key<W: Word>(key: Vec<u8>, rounds: u8) -> Vec<W> {
    // Init expanded key array with size t = 2(r+1)
    let mut expanded_key_table: Vec<W> = vec![W::zero(); 2 * (rounds as usize + 1)];

    // Step 1: Converting the Secret Key from Bytes to Words
    //let bytes_in_word: usize = (u32::BITS / u8::BITS) as usize;
    let byte_count: usize = key.len();
    let word_count: usize = max(byte_count, 1) / W::SIZE_IN_BYTES;
    let mut words: Vec<W> = vec![W::zero(); word_count];
    for i in (0..byte_count).rev() {
        let word_index = i / W::SIZE_IN_BYTES;
        words[word_index] = words[word_index]
            .rotate_left(8)
            .wrapping_add(&W::from(key[i]).expect("minimum word size is 8"));
    }

    // Step 2: Initializing the Array S
    expanded_key_table[0] = W::P;
    for i in 1..expanded_key_table.len() {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(&W::Q);
    }

    // Step 3: Mixing in the Secret Key
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut a: W = W::zero();
    let mut b: W = W::zero();

    for _ in 0..3 * max(expanded_key_table.len(), word_count) {
        a = expanded_key_table[i]
            .wrapping_add(&a)
            .wrapping_add(&b)
            .rotate_left(3);
        expanded_key_table[i] = a;
        b = words[j]
            .wrapping_add(&a)
            .wrapping_add(&b)
            .rotate_left(a.wrapping_add(&b).to_u128().unwrap() as u32);
        words[j] = b;

        i = (i + 1) % expanded_key_table.len();
        j = (j + 1) % word_count;
    }

    expanded_key_table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encode::<u32>(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode::<u32>(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode::<u32>(key, ct);
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode::<u32>(key, ct);
        assert!(&pt[..] == &res[..]);
    }
}
