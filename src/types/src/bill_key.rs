// @file: bill_key.rs
// @author: Krisna Pranav

use crypto::id::BillId;
use error::Result;

const BLOCK_BILL: &str = "/bl/";

pub struct BillKey<'a>(pub &'a BillId);
impl<'a> BillKey<'a> {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded_key = BLOCK_BILL.as_bytes().to_vec();
        encoded_key.extend_from_slice(self.0.as_ref());
        Ok(encoded_key)
    }
}
