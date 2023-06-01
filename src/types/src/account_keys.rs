// @file: account_keys.rs
// @author: Krisna Pranav

use super::ensure_len_eq;
use crypto::address::{NanoAddress, NANO_ADDRESS_LENGTH};
use error::{NanoError, Result};

const ACCOUNT_ID: &str = "/ac/";

pub struct AccountKey<'a>(pub &'a NanoAddress);
const ACCOUNT_KEY_SIZE: usize = NANO_ADDRESS_LENGTH + ACCOUNT_ID.len();

impl<'a> AccountKey<'a> {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded_key = ACCOUNT_ID.as_bytes().to_vec();
        encoded_key.extend_from_slice(self.0.as_ref());
        Ok(encoded_key)
    }

    pub fn decode(data: &[u8]) -> Result<NanoAddress> {
        ensure_len_eq(data, ACCOUNT_KEY_SIZE)
            .map_err(|e| NanoError::KeyCodecError(format!("{}", e)))?;
        let data_slice: &[u8; NANO_ADDRESS_LENGTH] = &data[ACCOUNT_ID.len()..]
            .try_into()
            .expect("slice with incorrect length");
        let addr = NanoAddress::from(data_slice);
        Ok(addr)
    }
}