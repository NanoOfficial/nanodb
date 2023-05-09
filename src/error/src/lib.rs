// @file: lib.rs
// @author: Krisna Pranav

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NanoError {
    #[error("invalid db address")]
    InvalidAddress,
    #[error("fail to require lock from state")]
    StateLockBusyError,
    #[error("fail to load key pair")]
    LoadKeyPairError,
}

pub type Result<T> = std::result::Result<T, NanoError>;