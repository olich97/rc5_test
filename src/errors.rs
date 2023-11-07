use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key length of {0}, must be less than 256 bytes and greater than 0")]
    InvalidKeyLength(usize),
    #[error("Invalid byte at position {0} in a key")]
    InvalidKeyByte(usize),
    #[error("Invalid input text")]
    InvalidInputText,
    #[error("Invalid conversion between types")]
    InvalidCast,
}
