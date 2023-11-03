use std::{cmp::max, convert::TryInto};

const ROUNDS: u8 = 12;
const P32: u32 = 0xb7e15163;
const Q32: u32 = 0x9e3779b9;
/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    let bytes_in_word = (u32::BITS / u8::BITS) as usize;
    let extended_key_table = expand_key(key, ROUNDS);
    // init A and B
    let mut a = u32::from_le_bytes(plaintext[..bytes_in_word].try_into().unwrap())
        .wrapping_add(extended_key_table[0]);
    let mut b = u32::from_le_bytes(plaintext[bytes_in_word..].try_into().unwrap())
        .wrapping_add(extended_key_table[1]);

    for i in 1..=ROUNDS.into() {
        a = (a ^ b)
            .rotate_left(b)
            .wrapping_add(extended_key_table[2 * i]);
        b = (b ^ a)
            .rotate_left(a)
            .wrapping_add(extended_key_table[2 * i + 1]);
    }

    let mut ciphertext = Vec::from(a.to_le_bytes().as_ref());
    ciphertext.extend_from_slice(b.to_le_bytes().as_ref());
    ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let bytes_in_word = (u32::BITS / u8::BITS) as usize;
    let extended_key_table = expand_key(key, ROUNDS);

    let mut a = u32::from_le_bytes(ciphertext[..bytes_in_word].try_into().unwrap());
    let mut b = u32::from_le_bytes(ciphertext[bytes_in_word..].try_into().unwrap());

    for i in (1..=ROUNDS.into()).rev() {
        b = b
            .wrapping_sub(extended_key_table[2 * i + 1])
            .rotate_right(a)
            ^ a;
        a = a.wrapping_sub(extended_key_table[2 * i]).rotate_right(b) ^ b;
    }

    a = a.wrapping_sub(extended_key_table[0]);
    b = b.wrapping_sub(extended_key_table[1]);

    let mut plaintext = Vec::from(a.to_le_bytes().as_ref());
    plaintext.extend_from_slice(b.to_le_bytes().as_ref());
    plaintext
}

/*
 * The key-expansion routine: expands the user's secret key K to fill the expanded key array S
 * so that S resembles an array of t = 2(r+1) random binary words defined by K
 */
fn expand_key(key: Vec<u8>, rounds: u8) -> Vec<u32> {
    // Init expanded key array with size t = 2(r+1)
    let mut expanded_key_table: Vec<u32> = vec![0; 2 * (rounds as usize + 1)];

    // Step 1: Converting the Secret Key from Bytes to Words
    let bytes_in_word: usize = (u32::BITS / u8::BITS) as usize;
    let byte_count: usize = key.len();
    let word_count: usize = max(byte_count, 1) / bytes_in_word;
    let mut words: Vec<u32> = vec![0; word_count];
    for i in (0..byte_count).rev() {
        let word_index = i / bytes_in_word;
        words[word_index] = words[word_index].rotate_left(8).wrapping_add(key[i].into());
    }

    // Step 2: Initializing the Array S
    expanded_key_table[0] = P32;
    for i in 1..expanded_key_table.len() {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(Q32);
    }

    // Step 3: Mixing in the Secret Key
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut a: u32 = 0;
    let mut b: u32 = 0;

    for _ in 0..3 * max(expanded_key_table.len(), word_count) {
        a = expanded_key_table[i]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(3);
        expanded_key_table[i] = a;
        b = words[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(a.wrapping_add(b));
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
        let res = encode(key, pt);
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
        let res = encode(key, pt);
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
        let res = decode(key, ct);
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
        let res = decode(key, ct);
        assert!(&pt[..] == &res[..]);
    }
}
