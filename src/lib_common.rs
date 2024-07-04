use rand::RngCore;
use hmac::{Hmac, Mac};
use rand_core;
use sha2::Sha256;
use digest::CtOutput;
use crypto_box::{PublicKey, SecretKey};

type HmacSha256 = Hmac<Sha256>;

pub const N: usize = 3; // Number of servers
pub const HMAC_OUTPUT_LEN: usize = std::mem::size_of::<CtOutput<HmacSha256>>();
pub const CTX_LEN: usize = 10; // Size of context string, in bytes

pub(crate) fn com_commit(r: &[u8], m: &str) -> Vec<u8> {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let out = com.finalize();

    out.into_bytes().to_vec()
}

pub(crate) fn com_open(c: &Vec<u8>, m: &str, r: &[u8]) -> bool {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let t = com.finalize();

    t.into_bytes().to_vec() == *c
}

pub(crate) fn mac_keygen() -> [u8; 32] {
    let mut k: [u8; 32] = [0; 32];
    rand_core::OsRng.fill_bytes(&mut k);

    k
}

pub(crate) fn mac_sign(k: &[u8; 32], m: &Vec<u8>) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let sigma = mac.finalize().into_bytes().to_vec();

    sigma
}

pub(crate) fn mac_verify(k: &[u8; 32], m: &Vec<u8>, sigma: Vec<u8>) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let t = mac.finalize().into_bytes().to_vec();

    let valid = sigma == t;

    valid
}

pub(crate) fn onion_encrypt(pks: Vec<PublicKey>, m: Vec<u8>) -> Vec<u8> {
    let mut ct = m.clone();
    for i in 0..pks.len() {
        let pki = &pks[i];
        ct = pki.seal(&mut rand_core::OsRng, &ct).unwrap();
    }

    ct
}

pub(crate) fn onion_peel(sk: SecretKey, ct: Vec<u8>) -> Vec<u8> {
    sk.unseal(&ct).unwrap()
}