// use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::ristretto::RistrettoPoint;
// use curve25519_dalek::constants as dalek_constants;
use rand::{rngs::{OsRng, StdRng}, Rng};
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore},
    Aes256Gcm, Key
};
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use sha3::{Sha3_512, Digest}; // our random oracle

type HmacSha256 = Hmac<Sha256>;
type CtOutput = hmac::digest::Output<HmacSha256>;

// lazy_static! {
//     pub static ref G: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
// }

const N: u8 = 3; // Number of servers

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    sks: Vec<Key<Aes256Gcm>> // Keys for servers along onion route
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

impl Client {

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: Vec<Key<Aes256Gcm>>) -> (Vec<u8>, CtOutput, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let mut ro = Sha3_512::new();
        ro.update(s);
        let result = ro.finalize();

        let k_f = <[u8; 64]>::from(result)[0..31].try_into().unwrap();
        let sp = <[u8; 64]>::from(result)[32..63].try_into().unwrap();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(b"aoeu").expect("");
        mac.update(message.as_bytes());
        let result = mac.finalize();

        a, b, c
    }

    // pub fn read(k_r: Key<Aes256Gcm>, c_1: <ciphertext type here>, mrt: (<bitstring>, <ciphertext>)) -> str, Report {

    // }
}
