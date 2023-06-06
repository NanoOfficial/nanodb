// @file: key.rs
// @author: Krisna Pranav

use crypto::id::{DbId, DBID_LENGTH};
use error::{NanoError, Result};

pub struct DbKey(pub DbId);

const DATABASE: &str = "/db/";

impl DbKey {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded_key = DATABASE.as_bytes().to_vec();
        encoded_key.extend_from_slice(self.0.as_ref());
        Ok(encoded_key)
    }

    #[allow(dead_code)]
    pub fn decode(data: &[u8]) -> Result<Self> {
        const MIN_KEY_TOTAL_LEN: usize = DBID_LENGTH + DATABASE.len();
        if data.len() < MIN_KEY_TOTAL_LEN {
            return Err(NanoError::KeyCodecError(
                "the length of data is invalid".to_string(),
            ));
        }
        let address_offset = DATABASE.len();
        let data_slice: &[u8; DBID_LENGTH] = &data[address_offset..address_offset + DbId::length()]
            .try_into()
            .map_err(|e| NanoError::KeyCodecError(format!("{e}")))?;
        let id = DbId::from(data_slice);
        Ok(Self(id))
    }

    #[allow(dead_code)]
    #[inline]
    pub fn max() -> Self {
        DbKey(DbId::max_id())
    }

    #[allow(dead_code)]
    #[inline]
    pub fn min() -> Self {
        DbKey(DbId::min_id())
    }
}
