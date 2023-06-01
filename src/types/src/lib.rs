// @file: lib.rs
// @author: Krisna Pranav

use anyhow::{ensure, Result};

pub fn ensure_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}

pub mod account_keys;
pub mod bill_key;
pub mod cost;
pub mod token;