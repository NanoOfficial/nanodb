use super::get_address_from_pk;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use ethereum_types::Address as AccountAddress;
use hex::FromHex;
use rand::Rng;

pub fn get_a_random_nonce() -> u64 {
    let mut rng = rand::thread_rng();
    let nonce = rng.gen_range(0..100000000);
    nonce
}

pub fn get_a_static_address() -> AccountAddress {
    let kp = get_a_static_keypair();
    get_address_from_pk(&kp.public)
}