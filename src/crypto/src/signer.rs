// @file: signer.rs
// @author: Krisna Pranav

use error::Result;
use ed25519_dalek::{Keypair, Signature, Signer, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

pub struct Db33Signer {
    kp: Keypair,
}

impl Db33Signer {
    pub fn new(kp: Keypair) -> Self {
        Self { kp }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<([u8; SIGNATURE_LENGTH], [u8; PUBLIC_KEY_LENGTH])> {
        let signature: Signature = self.kp.sign(msg);
        Ok((signature.to_bytes(), self.kp.public.to_bytes()))
    }
}