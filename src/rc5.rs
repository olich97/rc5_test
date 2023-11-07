use crate::word::Word;
use std::{cmp::max, convert::TryInto};

pub struct RC5<W> {
    expanded_key_table: Vec<W>,
    rounds: u8,
}

/// RC5 Cipher
///
/// This is the generic RC5 implementation with dynamic word size and ruound number parameters.
/// The word size is calculated from a type parameter, which must implement the Word trait.
/// The key size is derived by the length of specified key slice.
impl<W: Word> RC5<W> {
    /// Creates a new RC5 instance with the given key and number of rounds.
    ///
    /// # Arguments
    ///
    /// * `key` - The key used for encryption and decryption.
    /// * `rounds` - The number of rounds to perform during encryption and decryption.
    ///
    /// # Returns
    ///
    /// A new RC5 instance.
    pub fn new(key: Vec<u8>, rounds: u8) -> Self {
        Self {
            expanded_key_table: Self::expand_key(key, rounds),
            rounds,
        }
    }

    /// Encrypts the given plaintext and returns the corresponding ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt.
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext.
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        // Split the plaintext into two w-bit blocks: A and B.
        // A = A + S[0];
        let mut a = W::from_le_bytes(plaintext[..W::SIZE_IN_BYTES].try_into().unwrap())
            .wrapping_add(&self.expanded_key_table[0]);
        // B = B + S[1];
        let mut b = W::from_le_bytes(plaintext[W::SIZE_IN_BYTES..].try_into().unwrap())
            .wrapping_add(&self.expanded_key_table[1]);
        // for i = 1 to r do
        for i in 1..=self.rounds.into() {
            // A = ((A ⊕ B) < B) + S[2 ∗ i];
            a = (a ^ b)
                .rotate_left(b.to_u32().unwrap())
                .wrapping_add(&self.expanded_key_table[2 * i]);
            // B = ((B ⊕ A) < A) + S[2 ∗ i + 1];
            b = (b ^ a)
                .rotate_left(a.to_u32().unwrap())
                .wrapping_add(&self.expanded_key_table[2 * i + 1]);
        }

        let mut ciphertext = W::to_le_bytes(&a); //a.to_le_bytes().as_ref());
        ciphertext.extend_from_slice(&W::to_le_bytes(&b));
        ciphertext
    }

    /// Decrypts the given ciphertext and returns the corresponding plaintext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Vec<u8> {
        // Split the ciphertext into two w-bit blocks: A and B.
        let mut a = W::from_le_bytes(&ciphertext[..W::SIZE_IN_BYTES]);
        let mut b = W::from_le_bytes(&ciphertext[W::SIZE_IN_BYTES..]);
        // for i=r downto 1 do
        for i in (1..=self.rounds.into()).rev() {
            // B = ((B − S[2 ∗ i + 1]) > A) ⊕ A;
            b = b
            .wrapping_sub(&self.expanded_key_table[2 * i + 1])
            .rotate_right(a.to_u32().unwrap()) // not sure if works
            ^ a;
            // A = ((A − S[2 ∗ i]) > B) ⊕ B;
            a = a
                .wrapping_sub(&self.expanded_key_table[2 * i])
                .rotate_right(b.to_u32().unwrap())
                ^ b;
        }
        // B = B − S[1];
        b = b.wrapping_sub(&self.expanded_key_table[1]);
        // A = A − S[0]
        a = a.wrapping_sub(&self.expanded_key_table[0]);

        let mut plaintext = W::to_le_bytes(&a);
        plaintext.extend_from_slice(&W::to_le_bytes(&b));
        plaintext
    }

    /*
     * The key-expansion routine: expands the user's secret key K to fill the expanded key array S
     * so that S resembles an array of t = 2(r+1) random binary words defined by K
     */
    fn expand_key(key: Vec<u8>, rounds: u8) -> Vec<W> {
        // Init expanded key array with size t = 2(r+1)
        let mut expanded_key_table: Vec<W> = vec![W::zero(); 2 * (rounds as usize + 1)];

        // Step 1: Converting the Secret Key from Bytes to Words
        let byte_count: usize = key.len();
        //  c = [max(b, 1) / u]
        let word_count: usize = max(byte_count, 1) / W::SIZE_IN_BYTES;
        let mut words: Vec<W> = vec![W::zero(); word_count];
        // for i = b - 1 downto 0 do
        for i in (0..byte_count).rev() {
            let word_index = i / W::SIZE_IN_BYTES;
            // L[i/u] = (L[i/u] <<< 8) + K[i]
            words[word_index] = words[word_index]
                .rotate_left(8)
                .wrapping_add(&W::from(key[i]).expect("minimum word size is 8"));
        }

        // Step 2: Initializing the Array S
        // S[0] = Pw;
        expanded_key_table[0] = W::P;
        // for i = 1 to t − 1 do
        for i in 1..expanded_key_table.len() {
            // S[i] = S[i − 1] + Qw;
            expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(&W::Q);
        }

        // Step 3: Mixing in the Secret Key
        // i = j = 0
        let mut i: usize = 0;
        let mut j: usize = 0;
        // A = B = 0
        let mut a: W = W::zero();
        let mut b: W = W::zero();
        // do 3 * max(t, c) times:
        for _ in 0..3 * max(expanded_key_table.len(), word_count) {
            // A = S[i] = (S[i] + A + B) <<< 3
            a = expanded_key_table[i]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_left(3);
            expanded_key_table[i] = a;
            // B = L[j] = (L[j] + A + B) <<< (A + B)
            b = words[j]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_left(a.wrapping_add(&b).to_u128().unwrap() as u32);
            words[j] = b;
            // i = (i + 1) mod t
            i = (i + 1) % expanded_key_table.len();
            //  j = (j + 1) mod c
            j = (j + 1) % word_count;
        }

        expanded_key_table
    }
}
