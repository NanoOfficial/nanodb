// @file: signature.rs
// @author: Krisna Pranav

use crate::address::Address;
use crate::public_key::PublicKeyScheme;
use crate::serde::Readable;
use crate::signature_scheme::SignatureScheme;
use error::{Error, Result};
use enum_dispatch::enum_dispatch;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::traits::KeyPair as KeypairTraits;
use fastcrypto::traits::{Authenticator, ToFromBytes, VerifyingKey};
use fastcrypto::Verifier;
use rust_secp256k1::{Message, Secp256k1};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, Bytes};
use signature::Signer;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;

#[enum_dispatch]
#[derive(Clone, JsonSchema, PartialEq, Eq, Hash)]
pub enum Signature {
    Ed25519DBSignature,
    Secp256k1DBSignature,
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();
        if serializer.is_human_readable() {
            let s = Base64::encode(bytes);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Base64::decode(&s).map_err(|e| Error::custom(e.to_string()))?
        } else {
            let data: Vec<u8> = Vec::deserialize(deserializer)?;
            data
        };
        Self::from_bytes(&bytes).map_err(|e| Error::custom(e.to_string()))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ed25519DBSignature(sig) => sig.as_ref(),
            Signature::Secp256k1DBSignature(sig) => sig.as_ref(),
        }
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, signature::Error> {
        match bytes.first() {
            Some(x) => {
                if x == &SignatureScheme::ED25519.flag() {
                    Ok(<Ed25519DBSignature as ToFromBytes>::from_bytes(bytes)
                        .map_err(|_| signature::Error::new())?
                        .into())
                } else if x == &SignatureScheme::Secp256k1.flag() {
                    Ok(<Secp256k1DBSignature as ToFromBytes>::from_bytes(bytes)
                        .map_err(|_| signature::Error::new())?
                        .into())
                } else {
                    Err(signature::Error::new())
                }
            }
            _ => Err(signature::Error::new()),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let flag = Base64::encode([self.scheme().flag()]);
        let s = Base64::encode(self.signature_bytes());
        let p = Base64::encode(self.public_key_bytes());
        write!(f, "{flag}@{s}@{p}")?;
        Ok(())
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Ed25519DBSignature(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1],
);

impl Default for Ed25519DBSignature {
    fn default() -> Self {
        Self([0; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1])
    }
}

impl AsRef<[u8]> for Ed25519DBSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Ed25519DBSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl signature::Signature for Ed25519DBSignature {
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, signature::Error> {
        if bytes.len() != Self::LENGTH {
            return Err(signature::Error::new());
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl DBSignatureInner for Ed25519DBSignature {
    type Sig = Ed25519Signature;
    type PubKey = Ed25519PublicKey;
    type KeyPair = Ed25519KeyPair;
    const LENGTH: usize = Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1;
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Secp256k1DBSignature(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1],
);

impl Secp256k1DBSignature {
    pub fn new_hashed(kp: &Secp256k1KeyPair, msg: &[u8]) -> Result<Vec<u8>> {
        let secp = Secp256k1::signing_only();
        let message = Message::from_slice(msg)
            .map_err(|e| Error::InvalidSignature(format!("bad message for {e}")))?;
        let sig = secp.sign_ecdsa_recoverable(&message, &kp.secret.privkey);
        let (recovery_id, sig) = sig.serialize_compact();
        let mut signature_bytes: Vec<u8> =
            Vec::with_capacity(Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1);
        let scheme = SignatureScheme::Secp256k1;
        signature_bytes.extend_from_slice(&[scheme.flag()]);
        signature_bytes.extend_from_slice(&sig);
        signature_bytes.extend_from_slice(&[recovery_id.to_i32() as u8]);
        signature_bytes.extend_from_slice(kp.public().as_ref());
        Ok(signature_bytes)
    }
}

impl AsRef<[u8]> for Secp256k1DBSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Secp256k1DBSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl signature::Signature for Secp256k1DBSignature {
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, signature::Error> {
        if bytes.len() != Self::LENGTH {
            return Err(signature::Error::new());
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl DBSignatureInner for Secp256k1DBSignature {
    type Sig = Secp256k1Signature;
    type PubKey = Secp256k1PublicKey;
    type KeyPair = Secp256k1KeyPair;
    const LENGTH: usize = Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1;
}

pub trait DBSignatureInner: Sized + signature::Signature + PartialEq + Eq + Hash {
    type Sig: Authenticator<PubKey = Self::PubKey>;
    type PubKey: VerifyingKey<Sig = Self::Sig> + DBPublicKeyScheme;
    type KeyPair: KeypairTraits<PubKey = Self::PubKey, Sig = Self::Sig>;
    const LENGTH: usize = Self::Sig::LENGTH + Self::PubKey::LENGTH + 1;
    const SCHEME: SignatureScheme = Self::PubKey::SIGNATURE_SCHEME;
    fn get_verification_inputs(&self) -> Result<(Self::Sig, Self::PubKey)> {
        let bytes = self.public_key_bytes();
        let pk = Self::PubKey::from_bytes(bytes)
            .map_err(|_| NanoError::KeyCodecError("Invalid public key".to_string()))?;
        
        let signature = Self::Sig::from_bytes(self.signature_bytes())
            .map_err(|err| NanoError::InvalidSignature(err.to_string()))?;
        Ok((signature, pk))
    }

    fn new(kp: &Self::KeyPair, message: &[u8]) -> Result<Self> {
        let sig = kp.try_sign(message).map_err(|_| {
            NanoError::InvalidSignature("Failed to sign valid message with keypair".to_string())
        })?;
        let mut signature_bytes: Vec<u8> = Vec::with_capacity(Self::LENGTH);
        signature_bytes
            .extend_from_slice(&[<Self::PubKey as DBPublicKeyScheme>::SIGNATURE_SCHEME.flag()]);
        signature_bytes.extend_from_slice(sig.as_ref());
        signature_bytes.extend_from_slice(kp.public().as_ref());
        Self::from_bytes(&signature_bytes[..])
            .map_err(|err| NanoError::InvalidSignature(err.to_string()))
    }
}

#[enum_dispatch(Signature)]
pub trait DBSignature: Sized + signature::Signature {
    fn signature_bytes(&self) -> &[u8];
    fn public_key_bytes(&self) -> &[u8];
    fn scheme(&self) -> SignatureScheme;
    fn verify(&self, value: &[u8]) -> Result<DBAddress>;
}

pub trait Signable<W> {
    fn write(&self, writer: &mut W);
}

impl<S: DBSignatureInner + Sized> DBSignature for S {
    fn signature_bytes(&self) -> &[u8] {

        &self.as_ref()[1..1 + S::Sig::LENGTH]
    }

    fn public_key_bytes(&self) -> &[u8] {

        &self.as_ref()[S::Sig::LENGTH + 1..]
    }

    fn scheme(&self) -> SignatureScheme {
        S::PubKey::SIGNATURE_SCHEME
    }

    fn verify(&self, value: &[u8]) -> Result<DBAddress> {
        let (sig, pk) = &self.get_verification_inputs()?;
        pk.verify(value, sig)
            .map_err(|e| NanoError::InvalidSignature(format!("{e}")))?;
        Ok(DBAddress::from(pk))
    }
}