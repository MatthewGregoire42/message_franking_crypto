use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use rand::{OsRng, Rng};
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key
};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Sha256, Digest};


lazy_static! {
    pub static ref G: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    sks: Vec<Key<Aes256Gcm> // Keys for servers along onion route
}

#[derive(Serialize, Deserialize)]
pub struct Message<'a> {
    pub m: &'a str, // message text
    pub s: [u8; 32], // random seed
    pub c2: [u8; 32] // franking tag
}

#[derive(Serialize, Deserialize)]
pub struct Report<'a> {
    pub c2: [u8; 32], // franking tag
    pub kf: [u8; 32], // franking key
    pub sigma: [u8; 32], // reporting tag
    pub ctx: &'a str // message context
}

#[derive(Serialize, Deserialize)]
pub struct ModeratorPackage {
    pub k: Vec<u8>,
    pub tf: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionCiphertext {
    pub r: Vec<u8>,
    pub c1: RistrettoPoint,
    pub c2: Vec<u8>,
}

impl Client {

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: Vec<Key<Aes256Gcm>) -> (c1: Vec<u8>, c2: CtOutput, c3: Vec<u8>) {
        let mut rng = OsRng::new().expect("");
        let s = rng.next_u32();
    }
}
