use crate::address::{NanoAddress, NANO_ADDRESS_LENGTH};
use base64ct::Encoding as _;
use bson::Bson;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::Buf;
use error::{NanoError, Result};
use enum_primitive_derive::Primitive;
use fastcrypto::hash::{HashFunction, Sha3_256};
use num_traits::FromPrimitive;
use rust_secp256k1::hashes::{sha256, Hash};
use rust_secp256k1::ThirtyTwoByteHash;
use serde::Serialize;
use std::fmt;
use std::io::Cursor;
use storekey;

#[derive(Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub struct AccountId {
    pub addr: NanoAddress
}

impl AccountId {
    pub fn new(addr: NanoAddress) -> Self {
        Self { addr }
    }

    #[inline]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.addr.as_ref()))
    }
}

impl TryFrom<&[u8]> for AccountId {
    type Error = NanoError;
    fn try_from(data: &[u8]) -> std::result::Result<Self, NanoError> {
        Ok(Self {
            addr: NanoAddress::try_from(data)?,
        })
    }
}

pub const TX_ID_LENGTH: usize = 32;

#[derive(Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub struct TxId {
    data: [u8; TX_ID_LENGTH],
}

impl TxId {
    #[inline]
    pub fn zero() -> Self{
        Self {
            data: [0; TX_ID_LENGTH],
        }
    }

    pub fn to_base64(&self) -> String {
        base64ct::Base64::encode_string(self.as_ref())
    }
}