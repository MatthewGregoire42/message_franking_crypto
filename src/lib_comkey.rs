use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoBasepointTable, CompressedRistretto};
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::digest::Update;
use rand::{Rng, SeedableRng, RngCore};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha2;
use sha2_old::{Sha256, Sha512};
use sha3::{Sha3_256, Digest};
type HmacSha256 = Hmac<sha2::Sha256>;
type Point = RistrettoPoint;
use generic_array::{ArrayLength};
use digest::CtOutput;
use crypto_box::{PublicKey, SecretKey};
use typenum::consts::U12;
use generic_array::GenericArray;
use zkp::rand::rngs::OsRng as ZkpRng;


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
    static ref G0: Point = RistrettoPoint::hash_from_bytes::<Sha512>("base g0".as_bytes());
    static ref G1: Point = RistrettoPoint::hash_from_bytes::<Sha512>("base g1".as_bytes());
    static ref H: Point = RistrettoPoint::hash_from_bytes::<Sha512>("base h".as_bytes());
}

const N: usize = 3; // Number of servers

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    pks: Vec<PublicKey>, // Keys for servers along onion route
    sigma_k: CompressedRistretto // Commitment to server's k_m key
}

pub struct Moderator {
    sk: SecretKey,
    k_m: (Scalar, Scalar),
    r: Scalar,
    sigma_k: Point
}

pub struct Server {
    sk: SecretKey
}

pub(crate) fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub(crate) fn puzip(p: [u8; 32]) -> Point {
    CompressedRistretto::from_slice(&p).decompress().unwrap()
}

// The client can still use HMAC here (for performance reasons)
pub(crate) fn franking_com_commit(r: &[u8], m: &str) -> Vec<u8> {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let out = com.finalize();

    out.into_bytes().to_vec()
}

pub(crate) fn franking_com_open(c: &Vec<u8>, m: &str, r: &[u8]) -> bool {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let t = com.finalize();

    t.into_bytes().to_vec() == *c
}

// To compute sigma_k, the server computes an algebraic commitment to k_m = (x1, x2).
pub(crate) fn server_com_commit(r: Scalar, m: (Scalar, Scalar)) -> Point {
    let (x0, x1) = m;
    let res = (x0 * *G0) + (x1 * *G1) + (r * *H);

    res
}

pub(crate) fn mac_keygen() -> (Scalar, Scalar) {
    let x0 = Scalar::random(&mut ZkpRng);
    let x1 = Scalar::random(&mut ZkpRng);

    (x0, x1)
}

pub(crate) fn mac_sign(k: (Scalar, Scalar), m: &Vec<u8>) -> (Point, Point) {
    let (x0, x1) = k;

    let u = RistrettoPoint::random(&mut ZkpRng); // disallow one?
    let up = u * (x0 + Scalar::hash_from_bytes::<Sha512>(&m)*x1);
    let sigma = (u, up);

    sigma
}

pub(crate) fn mac_verify(k: (Scalar, Scalar), m: &Vec<u8>, sigma: (Point, Point)) -> bool {
    let (x0, x1) = k;

    let (u, up) = sigma;
    let res = up == u*(x0 + Scalar::hash_from_bytes::<Sha512>(&m)*x1);
    res
}

// Client operations

impl Client {
    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: &Vec<PublicKey>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let mut rs: [u8; 32+N] = [0; 32+N]; // TODO: size appropriately when size of mrt is determined
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..32];

        let c2 = franking_com_commit(k_f, message);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, s)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        let mut c3: Vec<u8> = Vec::new();
        for i in 0..N {
            let pk = &pks[i];
            let ri = [rs[i]]; // TODO: fix once size of r_is is known
            let payload = bincode::serialize(&(c3, ri)).unwrap();
            c3 = pk.seal(&mut rand_core::OsRng, &payload).unwrap();
        }

        (c1, c2, c3)
    }

    // c2 is found inside st.
    pub fn read(&self, k_r: Key<Aes256Gcm>, c1: Vec<u8>, st: (Vec<u8>, Vec<u8>)) -> (String, String, (Vec<u8>, Vec<u8>), Vec<u8>) {

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

        let (c2, ctx, sigma_bytes, pi_bytes) = rt;
        let pi: comkey_proof::CompactProof = bincode::deserialize(&pi_bytes).unwrap();
        let sigma = (CompressedRistretto::from_slice(&sigma_bytes[0..32]),
            CompressedRistretto::from_slice(&sigma_bytes[32..]));

        let mut proof_transcript = zkp::Transcript::new(b"pi_sigma");

        // Verify franking tag
        assert!(franking_com_open(&c2, m, k_f));

        // Validate the proof pi
        let v_val = (&(sigma.0.decompress().unwrap()) *
            &Scalar::hash_from_bytes::<Sha512>(&[&c2, ctx.as_bytes()].concat())).compress();
        assert!(comkey_proof::verify_compact(&pi, &mut proof_transcript, comkey_proof::VerifyAssignments { u: &sigma.0, up: &sigma.1, v: &v_val, g0: &G0.compress(), g1: &G1.compress(), h: &H.compress(), sigma_k: &self.sigma_k }).is_ok());

        let rd = (k_f.to_vec(), c2);

        (m.to_string(), ctx.to_string(), rd, sigma_bytes)
    }
}

// Moderator operations

impl Moderator {
    pub fn mod_process(&self, k_m: (Scalar, Scalar), c2: Vec<u8>, ctx: &str) -> (Vec<u8>, Vec<u8>) {
        let sigma = mac_sign(k_m, &[&c2, ctx.as_bytes()].concat());

        let sigma_zip = [pzip(sigma.0), pzip(sigma.1)].concat();

        let mut proof_transcript = zkp::Transcript::new(b"pi_sigma");
        let (pi, _) = comkey_proof::prove_compact(
            &mut proof_transcript,
            comkey_proof::ProveAssignments {
                x0: &k_m.0,
                x1: &k_m.1,
                u: &sigma.0,
                up: &sigma.1,
                r: &self.r,
                v: &(&sigma.0*Scalar::hash_from_bytes::<Sha512>(&[&c2, ctx.as_bytes()].concat())),
                g0: &G0,
                g1: &G1,
                h: &H,
                sigma_k: &self.sigma_k
            }
        );

        let pi_bytes = bincode::serialize(&pi).expect("");

        (sigma_zip, pi_bytes)
    }

    pub fn moderate(k_m: (Scalar, Scalar), m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma_zip: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let sigma = (puzip(sigma_zip[0..32].try_into().unwrap()), 
            puzip(sigma_zip[32..].try_into().unwrap()));

        let valid_f = franking_com_open(&c2, m, &k_f);
        let valid_r = mac_verify(k_m, &[&c2, ctx.as_bytes()].concat(), sigma);

        valid_f && valid_r
    }
}

// Server operations

pub trait ServerCore {

    fn process(sk_i: SecretKey, st_i_minus_1: (Vec<u8>, Vec<u8>)) -> (Vec<u8>, Vec<u8>) {
        let (c3, mrt) = st_i_minus_1;

        let res = sk_i.unseal(&c3).unwrap();
        let payload = bincode::deserialize::<(Vec<u8>, [u8; 1])>(&res).unwrap();
        let (c3_prime, ri) = payload;

        let mrt_prime: Vec<u8> = mrt // mrt_prime = mrt XOR ri
            .iter()
            .zip(ri.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        
        let st_i = (c3_prime, mrt_prime);

        st_i
    }

}

impl ServerCore for Server {}

impl ServerCore for Moderator {}