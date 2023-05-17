// @file: address.rs
// @author: Krisna Pranav

use crate::public_key::{NanoPublicKey, NanoPublicKeyScheme};
use crate::serde::Readable;
use error::NanoError;
use fastcrypto::encoding::{decode_bytes_hex, Encoding, Hex};
use fastcrypto::hash::{HashFunction, Sha3_256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub const NANO_ADDRESS_LENGTH: usize = 20;

#[serde_as]
#[derive(
    Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct NanoAddress(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<Hex, _>")]
    [u8; NANO_ADDRESS_LENGTH],
);

impl NanoAddress {
    pub const ZERO: Self = Self([0u8; NANO_ADDRESS_LENGTH]);

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn optional_address_as_hex<S>(
        key: &Option<NanoAddress>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&key.map(Hex::encode).unwrap_or_default())
    }

    pub fn optional_address_from_hex<'de, D>(
        deserializer: D,
    ) -> Result<Option<NanoAddress>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = decode_bytes_hex(&s).map_err(serde::de::Error::custom)?;
        Ok(Some(value))
    }

    pub fn to_inner(self) -> [u8; NANO_ADDRESS_LENGTH] {
        self.0
    }
    #[inline]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0.as_ref()))
    }
}

impl TryFrom<Vec<u8>> for NanoAddress {
    type Error = NanoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let arr: [u8; NANO_ADDRESS_LENGTH] =
            bytes.try_into().map_err(|_| NanoError::InvalidAddress)?;
        Ok(Self(arr))
    }
}

impl From<&[u8; NANO_ADDRESS_LENGTH]> for NanoAddress {
    fn from(data: &[u8; NANO_ADDRESS_LENGTH]) -> Self {
        Self(*data)
    }
}

impl From<&NanoPublicKey> for NanoAddress {
    fn from(pk: &NanoPublicKey) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update([pk.flag()]);
        hasher.update(pk);
        let g_arr = hasher.finalize();
        let mut res = [0u8; NANO_ADDRESS_LENGTH];
        res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..NANO_ADDRESS_LENGTH]);
        NanoAddress(res)
    }
}

impl<T: NanoPublicKeyScheme> From<&T> for NanoAddress {
    fn from(pk: &T) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update([T::SIGNATURE_SCHEME.flag()]);
        hasher.update(pk);
        let g_arr = hasher.finalize();
        let mut res = [0u8; NANO_ADDRESS_LENGTH];
        res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..NANO_ADDRESS_LENGTH]);
        NanoAddress(res)
    }
}

impl TryFrom<&[u8]> for NanoAddress {
    type Error = NanoError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, NanoError> {
        let arr: [u8; NANO_ADDRESS_LENGTH] =
            bytes.try_into().map_err(|_| NanoError::InvalidAddress)?;
        Ok(Self(arr))
    }
}

impl TryFrom<&str> for NanoAddress {
    type Error = NanoError;
    fn try_from(addr: &str) -> std::result::Result<Self, NanoError> {
        let value = decode_bytes_hex(addr).map_err(|_| NanoError::InvalidAddress)?;
        Ok(Self(value))
    }
}

impl AsRef<[u8]> for NanoAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}