// @file: account_store.rs
// @author: Krisna Pranav


use bytes::BytesMut;
use crypto::address::NanoAddress;
use error::{NanoError, Result};
use proto::account_proto::Account;
use types::{account_keys::AccountKey, token};
use merkdb::{Merk, Op};
use prost::Message;
use std::pin::Pin;

pub struct AccountStore {}

impl AccountStore {
    pub fn new() -> Self {
        Self {}
    }

    fn override_account(db: Pin<&mut Merk>, encoded_key: Vec<u8>, account: &Account) -> Result<()> {
        let mut buf = BytesMut::with_capacity(1024);
        account
            .encode(&mut buf)
            .map_err(|e| NanoError::ApplyAccountError(format!("{}", e)))?;
        let buf = buf.freeze();
        let entry = (encoded_key, Op::Put(buf.to_vec()));
        unsafe {
            Pin::get_unchecked_mut(db)
                .apply(&[entry], &[])
                .map_err(|e| NanoError::ApplyAccountError(format!("{}", e)))?;
        }
        Ok(())
    }

    pub fn update_account(db: Pin<&mut Merk>, addr: &NanoAddress, account: &Account) -> Result<()> {
        let key = AccountKey(addr);
        let encoded_key = key.encode()?;
        Self::override_account(db, encoded_key, account)
    }

    pub fn new_account(db: Pin<&mut Merk>, addr: &NanoAddress, credits: u64) -> Result<Account> {
        let key = AccountKey(addr);
        let encoded_key = key.encode()?;
        let values = db
            .get(encoded_key.as_ref())
            .map_err(|e| NanoError::GetAccountError(format!("{}", e)))?;
        if let Some(v) = values {
            match Account::decode(v.as_ref()) {
                Ok(a) => Ok(a),
                Err(e) => Err(NanoError::GetAccountError(format!("{}", e))),
            }
        } else {
            let new_account = Account {
                bills: 0,
                credits: credits * token::TOKEN_COVERSION,
                total_storage_in_bytes: 0,
                total_mutation_count: 0,
                total_session_count: 0,
                nonce: 0,
            };
            Self::override_account(db, encoded_key, &new_account)?;
            Ok(new_account)
        }
    }

    fn get_account_internal(db: Pin<&Merk>, key: &[u8]) -> Result<Option<Account>> {
        let values = db
            .get(key)
            .map_err(|e| NanoError::GetAccountError(format!("{}", e)))?;
        if let Some(v) = values {
            match Account::decode(v.as_ref()) {
                Ok(a) => Ok(Some(a)),
                Err(e) => Err(NanoError::GetAccountError(format!("{}", e))),
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_account(db: Pin<&Merk>, addr: &NanoAddress) -> Result<Option<Account>> {
        let key = AccountKey(addr);
        let encoded_key = key.encode()?;
        Self::get_account_internal(db, encoded_key.as_ref())
    }
}
