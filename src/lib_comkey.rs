use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
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
use sha2_old::Sha512;
type HmacSha256 = Hmac<sha2::Sha256>;
type Point = RistrettoPoint;
use crypto_box::{PublicKey, SecretKey};
use zkp::rand::rngs::OsRng as ZkpRng;
use zkp::CompactProof;

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

use crate::lib_common::{N, CTX_LEN, com_commit, com_open, ServerCore};
// const SIGMA_LEN: usize = std::mem::size_of::<(Point, Point)>();
// const PROOF_LEN: usize = std::mem::size_of::<CompactProof>();
// const MRT_LEN: usize = HMAC_OUTPUT_LEN + CTX_LEN + SIGMA_LEN + PROOF_LEN;
const MRT_LEN: usize = 264 + CTX_LEN;
const KF_LEN: usize = 32; // HMAC can be instantiated with variable size keys
const RS_SIZE: usize = KF_LEN + MRT_LEN*N;

pub struct Client {
    pub uid: u32,
    pub k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    pub pks: Vec<PublicKey>, // Keys for servers along onion route
    pub sigma_k: CompressedRistretto // Commitment to server's k_m key
}

pub struct Moderator {
    pub sk: SecretKey,
    pub k_m: (Scalar, Scalar),
    pub r: Scalar,
    pub sigma_k: Point
}

impl ServerCore for Moderator {}

pub fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn puzip(p: [u8; 32]) -> Point {
    CompressedRistretto::from_slice(&p).decompress().unwrap()
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

pub(crate) fn mac_sign(k: &(Scalar, Scalar), m: &Vec<u8>) -> (Point, Point) {
    let (x0, x1) = k;

    let u = RistrettoPoint::random(&mut ZkpRng); // disallow one?
    let up = u * (x0 + Scalar::hash_from_bytes::<Sha512>(&m)*x1);
    let sigma = (u, up);

    sigma
}

pub(crate) fn mac_verify(k: &(Scalar, Scalar), m: &Vec<u8>, sigma: (Point, Point)) -> bool {
    let (x0, x1) = k;

    let (u, up) = sigma;
    let res = up == u*(x0 + Scalar::hash_from_bytes::<Sha512>(&m)*x1);
    res
}

// Client operations

impl Client {
    pub fn new(k_r: Key<Aes256Gcm>, pks: Vec<PublicKey>, sigma_k: CompressedRistretto) -> Client {
        Client {
            uid: rand::random(),
            k_r: k_r,
            pks: pks,
            sigma_k: sigma_k
        }
    }

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: &Vec<PublicKey>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let mut rs: [u8; RS_SIZE] = [0; RS_SIZE];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..KF_LEN];

        let c2 = com_commit(k_f, message);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, s)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        let mut c3: Vec<u8> = Vec::new();
        for i in (0..N).rev() {
            let pk = &pks[i];
            let ri = &rs[KF_LEN+(i*MRT_LEN)..KF_LEN+((i+1)*MRT_LEN)];
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

        // println!("Read mrt: {:?}", mrt);

        // Re-generate values from the seed s
        let mut rs: [u8; RS_SIZE] = [0; RS_SIZE];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..KF_LEN];

        for i in 0..N {
            let r_i = &rs[KF_LEN+(i*MRT_LEN)..KF_LEN+((i+1)*MRT_LEN)];
            mrt.iter_mut() // mrt = mrt XOR r_i
                .zip(r_i.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
        }

        let rt = bincode::deserialize::<(Vec<u8>, &str, Vec<u8>, Vec<u8>)>(&mrt).unwrap();

        let (c2, ctx, sigma_bytes, pi_bytes) = rt;
        let pi: comkey_proof::CompactProof = bincode::deserialize(&pi_bytes).unwrap();
        let sigma = (CompressedRistretto::from_slice(&sigma_bytes[0..32]),
            CompressedRistretto::from_slice(&sigma_bytes[32..]));

        let mut proof_transcript = zkp::Transcript::new(b"pi_sigma");

        // Verify franking tag
        assert!(com_open(&c2, m, k_f));

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
    pub fn mod_process(&self, k_m: &(Scalar, Scalar), c2: &Vec<u8>, ctx: &str) -> (Vec<u8>, Vec<u8>) {
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

    pub fn moderate(k_m: &(Scalar, Scalar), m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma_zip: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let sigma = (puzip(sigma_zip[0..32].try_into().unwrap()), 
            puzip(sigma_zip[32..].try_into().unwrap()));

        let valid_f = com_open(&c2, m, &k_f);
        let valid_r = mac_verify(k_m, &[&c2, ctx.as_bytes()].concat(), sigma);

        valid_f && valid_r
    }

    pub fn new() -> Moderator {
        let k_m = mac_keygen();
        let r = Scalar::random(&mut ZkpRng);
        Moderator {
            sk: SecretKey::generate(&mut rand::rngs::OsRng),
            k_m: k_m,
            r: r,
            sigma_k: server_com_commit(r, k_m)
        }
    }

    pub fn get_pk(&self) -> PublicKey {
        self.sk.public_key()
    }
    
}