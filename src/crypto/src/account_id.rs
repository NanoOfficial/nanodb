// @file: account_id.rs
// @author: Krisna Pranav

use crate::address::NanoAddress;

pub struct AccountId {
    pub addr: NanoAddress,
}

impl AccountId {
    pub fn new(addr: NanoAddress) -> Self {
        Self { addr }
    }
}