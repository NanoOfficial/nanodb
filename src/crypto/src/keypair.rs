use crate::public_key::NanoPublicKey;
use crate::signature::{
    Secp256k1DBSignature, Signature, Ed25519DBSignature, DBSignatureInner
};
use crate::signature_scheme::SignatureScheme;
use error::NanoError;
use derive_more::From;
use eyre::eyre;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey};
pub use fastcrypto::traits::KeyPair as KeypairTraits;
pub use fastcrypto::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes,
    VerifyingKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use signature::Signer;

#[derive(Debug, From)]
pub enum KeyPair {
    Ed25519(Ed25519KeyPair),
    Secp256k1(Secp256k1KeyPair),
}

impl KeyPair {
    pub fn public(&self) -> NanoPublicKey {
        match self {
            KeyPair::Ed25519(kp) => NanoPublicKey::Ed25519(kp.public().clone()),
            KeyPair::Secp256k1(kp) => NanoPublicKey::Secp256k1(kp.public().clone()),
        }
    }
    pub fn try_sign_hashed_message(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, NanoError> {
        match self {
            KeyPair::Ed25519(_) => Err(NanoError::SignError(
                "signing hashed message is not supperted with ed25519".to_string(),
            )),
            KeyPair::Secp256k1(kp) => Secp256k1DBSignature::new_hashed(&kp, msg),
        }
    }
}

impl Signer<Signature> for KeyPair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        match self {
            KeyPair::Ed25519(kp) => kp.try_sign(msg),
            KeyPair::Secp256k1(kp) => kp.try_sign(msg),
        }
    }
}

impl FromStr for KeyPair {
    type Err = NanoError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| NanoError::KeyCodecError(format!("{}", e)))?;
        Ok(kp)
    }
}

impl EncodeDecodeBase64 for KeyPair {
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        match self {
            KeyPair::Ed25519(kp) => {
                let kp1 = kp.copy();
                bytes.extend_from_slice(&[self.public().flag()]);
                bytes.extend_from_slice(kp1.private().as_ref());
            }

            KeyPair::Secp256k1(kp) => {
                let kp1 = kp.copy();
                bytes.extend_from_slice(&[self.public().flag()]);
                bytes.extend_from_slice(kp1.private().as_ref());
            }
        }
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> std::result::Result<Self, eyre::Report> {
        let bytes = Base64::decode(value).map_err(|e| eyre!("{}", e.to_string()))?;
        match SignatureScheme::from_flag_byte(bytes.first().ok_or_else(|| eyre!("Invalid length"))?)
        {
            Ok(x) => match x {
                SignatureScheme::ED25519 => {
                    let sk = Ed25519PrivateKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )
                    .map_err(|_| eyre!("invalid secret"))?;
                    let kp = Ed25519KeyPair::from(sk);
                    Ok(KeyPair::Ed25519(kp))
                }
                SignatureScheme::Secp256k1 => {
                    let sk = Secp256k1PrivateKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )
                    .map_err(|_| eyre!("invalid secret"))?;
                    let kp = Secp256k1KeyPair::from(sk);
                    Ok(KeyPair::Secp256k1(kp))
                }
            },
            _ => Err(eyre!("Invalid bytes")),
        }
    }
}

impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.encode_base64();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        <KeyPair as EncodeDecodeBase64>::decode_base64(&s)
            .map_err(|e| Error::custom(e.to_string()))
    }
}

impl Signer<Signature> for Ed25519KeyPair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(Ed25519DBSignature::new(self, msg)
            .map_err(|_| signature::Error::new())?
            .into())
    }
}

impl Signer<Signature> for Secp256k1KeyPair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(Secp256k1DBSignature::new(self, msg)
            .map_err(|_| signature::Error::new())?
            .into())
    }
}
