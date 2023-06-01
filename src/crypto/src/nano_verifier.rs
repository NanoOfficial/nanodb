// @file: signer.rs
// @author: Krisna Pranav
use crate::address::NanoAddress;
use crate::public_key::NanoPublicKey;
use crate::signature::{NanoSignature, Signature};
use crate::id::AccountId;
use crate::signature_scheme::SignatureScheme;
use error::{NanoError, Result};
use fastcrypto::secp256k1::Secp256k1Signature;
use signature::Signature as _;

pub struct NanoVerifier {}

impl NanoVerifier {
    pub fn verify(msg: &[u8], signature_raw: &[u8]) -> Result<AccountId> {
        let signature = Signature::from_bytes(signature_raw)
            .map_err(|e| NanoError::InvalidSignature(format!("{e}")))?;
        let nano_address = signature.verify(&msg)?;
        Ok(AccountId::new(nano_address))
    }

    pub fn verify_hashed(hashed: &[u8], signature_raw: &[u8]) -> Result<AccountId> {
        let signature = Signature::from_bytes(signature_raw)
            .map_err(|e| NanoError::InvalidSignature(format!("fail to generate signature {e}")))?;
        let spk =
            NanoPublicKey::try_from_bytes(SignatureScheme::Secp256k1, signature.public_key_bytes())
                .map_err(|e| NanoError::InvalidSignature(format!("bad public key  {e}")))?;
        let sig = Secp256k1Signature::from_bytes(signature.signature_bytes())
            .map_err(|e| NanoError::InvalidSignature(format!("bad signature scheme {e}")))?;
        if let Signature::Secp256k1DBSignature(_) = signature {
            let nano_address = NanoAddress::from(&spk);
            if let NanoPublicKey::Secp256k1(internal_pk) = spk {
                internal_pk.verify_hashed(hashed, &sig).map_err(|e| {
                    NanoError::InvalidSignature(format!("invalid hashed message for {e}"))
                })?;
                Ok(AccountId::new(nano_address))
            } else {
                Err(NanoError::InvalidSignature("bad signature".to_string()))
            }
        } else {
            Err(NanoError::InvalidSignature(
                "bad signature secp256k1 expected".to_string(),
            ))
        }
    }
}
