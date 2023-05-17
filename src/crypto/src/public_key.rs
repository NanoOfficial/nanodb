// @file: public_key.rs
// @author: Krisna Pranav

use crate::signature_scheme::SignatureScheme;
use derive_more::From;
use eyre::eyre;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::encoding::Base64;
use fastcrypto::encoding::Encoding;
use fastcrypto::secp256k1::Secp256k1PublicKey;
use fastcrypto::traits::{EncodeDecodeBase64, ToFromBytes, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, From)]
pub enum NanoPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
}

impl AsRef<[u8]> for NanoPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            NanoPublicKey::Ed25519(pk) => pk.as_ref(),
            NanoPublicKey::Secp256k1(pk) => pk.as_ref(),
        }
    }
}

impl EncodeDecodeBase64 for NanoPublicKey {
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[self.flag()]);
        bytes.extend_from_slice(self.as_ref());
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> std::result::Result<Self, eyre::Report> {
        let bytes = Base64::decode(value).map_err(|e| eyre!("{}", e.to_string()))?;
        match bytes.first() {
            Some(x) => {
                if x == &SignatureScheme::ED25519.flag() {
                    let pk = Ed25519PublicKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?;
                    Ok(NanoPublicKey::Ed25519(pk))
                } else if x == &SignatureScheme::Secp256k1.flag() {
                    let pk = Secp256k1PublicKey::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?;
                    Ok(NanoPublicKey::Secp256k1(pk))
                } else {
                    Err(eyre!("Invalid flag byte"))
                }
            }
            _ => Err(eyre!("Invalid bytes")),
        }
    }
}

impl Serialize for NanoPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.encode_base64();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for NanoPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        <NanoPublicKey as EncodeDecodeBase64>::decode_base64(&s)
            .map_err(|e| Error::custom(e.to_string()))
    }
}

impl NanoPublicKey {
    pub fn flag(&self) -> u8 {
        self.scheme().flag()
    }

    pub fn try_from_bytes(
        curve: SignatureScheme,
        key_bytes: &[u8],
    ) -> std::result::Result<NanoPublicKey, eyre::Report> {
        match curve {
            SignatureScheme::ED25519 => Ok(NanoPublicKey::Ed25519(Ed25519PublicKey::from_bytes(
                key_bytes,
            )?)),
            SignatureScheme::Secp256k1 => Ok(NanoPublicKey::Secp256k1(
                Secp256k1PublicKey::from_bytes(key_bytes)?,
            )),
        }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            NanoPublicKey::Ed25519(_) => SignatureScheme::ED25519,
            NanoPublicKey::Secp256k1(_) => SignatureScheme::Secp256k1,
        }
    }
}

pub trait NanoPublicKeyScheme: VerifyingKey {
    const SIGNATURE_SCHEME: SignatureScheme;
}

impl NanoPublicKeyScheme for Ed25519PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
}

impl NanoPublicKeyScheme for Secp256k1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256k1;
}