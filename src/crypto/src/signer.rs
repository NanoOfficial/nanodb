// @file: signer.rs
// @author: Krisna Pranav

use crate::address::NanoAddress;
use crate::keypair::KeyPair;
use crate::signature::Signature;
use error::{NanoError, Result};
use ethers::core::types::transaction::eip712::{Eip712, TypedData};
use signature::Signer;

pub struct NanoMultiSchemeSigner {
    kp: KeyPair,
}

impl NanoMultiSchemeSigner {
    pub fn new(kp: KeyPair) -> Self {
        Self { kp }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let signature: Signature = self
            .kp
            .try_sign(msg)
            .map_err(|e| NanoError::SignMessageError(format!("{e}")))?;
        Ok(signature)
    }

    pub fn sign_typed_data(&self, typed_data: &TypedData) -> Result<Vec<u8>> {
        let hashed = typed_data.encode_eip712().map_err(|e| {
            NanoError::SignError(format!("fail to generate typed data hash for {e}"))
        })?;
        self.kp.try_sign_hashed_message(&hashed)
    }

    pub fn get_address(&self) -> Result<NanoAddress> {
        let pk = self.kp.public();
        Ok(NanoAddress::from(&pk))
    }
}
