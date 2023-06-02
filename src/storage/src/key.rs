// @file: key.rs
// @author: Krisna Pranav

use crypto::address::{NanoAddress, NANO_ADDRESS_LENGTH};
use error::{NanoError, Result};
const NAMESPACE: &str = "_NS_";
const MAX_USE_KEY_LEN: usize = 128 * 4;
const MAX_NAMESPACE_LEN: usize = 16;
const MIN_KEY_TOTAL_LEN: usize = NANO_ADDRESS_LENGTH + NAMESPACE.len();

pub struct Key<'a>(pub NanoAddress, pub &'a [u8], pub &'a [u8]);

impl<'a> Key<'a> {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.1.len() > MAX_NAMESPACE_LEN || self.2.len() > MAX_USE_KEY_LEN {
            return Err(NanoError::KeyCodecError(format!(
                "the length {} of namespace or key exceeds the limit",
                self.2.len()
            )));
        }
        let mut encoded_key = self.0.as_ref().to_vec();
        encoded_key.extend_from_slice(NAMESPACE.as_bytes());
        encoded_key.extend_from_slice(self.1);
        encoded_key.extend_from_slice(self.2);
        Ok(encoded_key)
    }

    pub fn decode(data: &'a [u8], ns: &'a [u8]) -> Result<Self> {
        // if data.len() <= MIN_KEY_TOTAL_LEN {
        //     Ok(result);
        // }

        let key_start_offset = MIN_KEY_TOTAL_LEN + ns.len();
        let data_slice: &[u8; NANO_ADDRESS_LENGTH] = &data[..NANO_ADDRESS_LENGTH]
            .try_into()
            .map_err(|e| NanoError::KeyCodecError(format!("{e}")))?;

        let addr = NanoAddress::from(data_slice);
        Ok(Self(addr, ns, &data[key_start_offset..]))
    }
}
