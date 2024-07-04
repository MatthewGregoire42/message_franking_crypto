use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoBasepointTable, CompressedRistretto};
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::traits::BasepointTable;
use rand::{Rng, SeedableRng, RngCore};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Digest};
type HmacSha256 = Hmac<Sha256>;
type Point = RistrettoPoint;
use generic_array::{ArrayLength};
use digest::CtOutput;
use crypto_box::PublicKey;
use typenum::consts::U12;
use generic_array::GenericArray;

define_proof! {
    comkey_proof,           // Proof name
    "CKP",                  // Proof label
    (x0, x1, r),            // Secret variables
    (u, up, v),             // Public variables specific to this proof
    (g0, g1, h, sigma_k) :  // Common public variables
    sigma_k = (x0 * g0 + x1 * g1 + r * h),
    up = (x0 * u + x1 * v)
}

lazy_static! {
    pub static ref G: &'static RistrettoBasepointTable = &dalek_constants::RISTRETTO_BASEPOINT_TABLE;
}

const N: usize = 3; // Number of servers

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    sks: Vec<Key<Aes256Gcm>> // Keys for servers along onion route
}

pub struct Moderator {
    k_m: [u8; 32]
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

pub(crate) fn mac_keygen() -> (Scalar, Scalar) {
    let x0 = Scalar::random(&mut rand_core::OsRng);
    let x1 = Scalar::random(&mut rand_core::OsRng);

    (x0, x1)
}

pub(crate) fn mac_sign(k: (Scalar, Scalar), m: &str) -> (Point, Point) {
    let x0 = k.0;
    let x1 = k.1;

    let u = RistrettoPoint::random(&mut rand_core::OsRng); // disallow one?
    let up = u * (x0 + Scalar::hash_from_bytes::<Sha512>(m.as_bytes())*x1);
    let sigma = (u, up);

    sigma
}

pub(crate) fn mac_verify(k: (Scalar, Scalar), m: &str, sigma: (Point, Point)) -> bool {
    let x0 = k.0;
    let x1 = k.1;

    let u = sigma.0;
    let up = sigma.1;

    let res = up == u*(x0 + Scalar::hash_from_bytes::<Sha512>(m.as_bytes())*x1);
    res
}

impl Client {

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: &Vec<PublicKey>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let mut rs: [u8; 32+N] = [0; 32+N]; // TODO: size appropriately when size of mrt is determined
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..32];

        let c2 = com_commit(k_f, message);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, s)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        let mut c3: Vec<u8> = Vec::new();
        for i in 0..N {
            let pk = &pks[i];
            let pt = &[c3, [rs[i]].to_vec()].concat();
            c3 = pk.seal(&mut rand_core::OsRng, pt).unwrap();
        }

        (c1, c2, c3)
    }

    // c2 is found inside st.
    pub fn read(k_r: Key<Aes256Gcm>, c1: Vec<u8>, st: (Vec<u8>, Vec<u8>)) -> (String, String, (Vec<u8>, Vec<u8>), Vec<u8>) {

        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&k_r);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, [u8; 32])>(&payload_bytes).unwrap();

        let (m, s) = payload;

        let mut mrt = st.1;

        // Re-generate values from the seed s
        let mut rs: [u8; 32+N] = [0; 32+N]; // TODO: size appropriately when size of mrt is determined
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..32];

        for i in 0..N {
            let r_i = [rs[32+i]]; // TODO: fix once r_i's size is known
            mrt.iter_mut() // mrt = mrt XOR r_i
                .zip(r_i.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
        }

        let rt = bincode::deserialize::<(Vec<u8>, &str, Vec<u8>, [u8; 32])>(&mrt).unwrap();

        let (c2, ctx, sigma, sigma_c) = rt;

        // Verify franking tag
        assert!(com_open(&c2, m, k_f));

        // Re-compute sigma_c to verify hash
        let mut hasher = sha3::Sha3_256::new();
        hasher.update([&sigma, &c2, ctx.as_bytes()].concat());
        let result = hasher.finalize();
        assert!(result.as_slice() == sigma_c);

        let rd = (k_f.to_vec(), c2);

        (m.to_string(), ctx.to_string(), rd, sigma)
    }
}

impl Moderator {
    pub fn mod_process(k_m: &[u8], c2: Vec<u8>, ctx: &str) -> (Vec<u8>, Vec<u8>) {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&k_m).expect("");
        mac.update(&[&c2, ctx.as_bytes()].concat());
        let sigma = mac.finalize().into_bytes().to_vec();

        let mut hasher = sha3::Sha3_256::new();
        hasher.update([&sigma, &c2, ctx.as_bytes()].concat());
        let sigma_c = hasher.finalize().as_slice().to_vec();

        (sigma, sigma_c)
    }

    pub fn moderate(k_m: &[u8], m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let valid_f = com_open(&c2, m, &k_f);
        let valid_r = mac_verify(k_m, (c_2, ctx), sigma);

        valid_f && valid_r
    }
}

// impl Server {
//     pub fn process(sk_i: Key<Aes256Gcm>, st_i_minus_1: (Vec<u8>, Vec<u8>)) -> (Vec<u8>, Vec<u8>) {

//     }
// }