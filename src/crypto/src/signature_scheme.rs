// @file: signature_scheme.rs
// @author: Krisna Pranav

use error::{Error, Result};

pub enum SignatureScheme {
    ED25519,
    Secp256k1, 
}

impl SignatureScheme {
    pub fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
        }
    }

    pub fn from_flag(flag: &str) -> Result<SignatureScheme> {
        let byte_int = flag
            .parse::<u8>()
            .map_err(|_| NanoError::KeyCodecError("Invalid key scheme".to_string()))?;
        Self::from_flag_byte(&byte_int)
    }

    pub fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            _ => Err(NanoError::KeyCodecError("Invalid key scheme".to_string())),
        }
    }
}