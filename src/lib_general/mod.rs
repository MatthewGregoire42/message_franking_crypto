use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoBasepointTable, CompressedRistretto};
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::traits::BasepointTable;
use rand::{Rng, SeedableRng};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;
type CtOutput = hmac::digest::Output<HmacSha256>;
type Point = RistrettoPoint;
use generic_array::{ArrayLength};

lazy_static! {
    pub static ref G: &'static RistrettoBasepointTable = &dalek_constants::RISTRETTO_BASEPOINT_TABLE;
}

const N: usize = 3; // Number of servers

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    sks: Vec<Key<Aes256Gcm>> // Keys for servers along onion route
}

pub struct Message<'a> {
    pub m: &'a str, // message text
    pub s: [u8; 32], // random seed
    pub c2: [u8; 32] // franking tag
}

pub struct Report<'a> {
    pub c2: [u8; 32], // franking tag
    pub kf: [u8; 32], // franking key
    pub sigma: [u8; 32], // reporting tag
    pub ctx: &'a str // message context
}

pub struct ModeratorPackage {
    pub k: Vec<u8>,
    pub tf: Vec<u8>,
}

pub(crate) fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub(crate) fn puzip(p: [u8; 32]) -> Point {
    CompressedRistretto::from_slice(&p).unwrap().decompress().unwrap()
}

impl Client {

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: Vec<Key<Aes256Gcm>>) -> (Vec<u8>, CtOutput, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let mut k_f: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut k_f);

        let mut rs: [u8; N] = [0; N];
        let g = rand::rngs::StdRng::from_seed(s);
        g.fill(&mut rs);

        let mut com = HmacSha256::new(&k_f).expect("");
        com.update(message.as_bytes());
        let c2 = com.finalize();

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let c2_vec: Vec<u8> = c2.clone().into_bytes().to_vec();
        let payload = bincode::serialize(&(message, s, c2_vec)).expect("");
        let c1 = cipher.encrypt(&nonce, payload.as_slice()).unwrap();

        let mut c3: &[u8] = &[0];
        for i in 0..N {
            let pk = pks[i];

        }

        (c1, c2, c3)
    }

    // pub fn read(k_r: Key<Aes256Gcm>, c1: Vec<u8>, st: (Vec<u8>, Vec<u8>)) -> (&str, &str, (Vec<u8>, Vec<u8>), CtOutput) {
        
    // }
}

// impl Moderator {
//     pub fn mod_process(k_m: Key<Aes256Gcm>, c2: Vec<u8>, ctx: &str) -> (CtOutput, Vec<u8>) {

//     }

//     pub fn moderate(k_m: Key<Aes256Gcm>, m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma: CtOutput) -> bool {

//     }
// }

// impl Server {
//     pub fn process(sk_i: Key<Aes256Gcm>, st_i_minus_1: (Vec<u8>, Vec<u8>)) -> (Vec<u8>, Vec<u8>) {

//     }
// }