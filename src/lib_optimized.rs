use rand::{Rng, SeedableRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha3::Digest;
use crypto_box::{PublicKey, SecretKey};

use crate::lib_common::*;

// const SIGMA_C_LEN: usize = std::mem::size_of::<GenericArray<u8, U32>>();
// const MRT_LEN: usize = size_of::<(CtOutput<HmacSha256>,
//                                   [u8; 10],
//                                   CtOutput<HmacSha256>,
//                                   GenericArray<u8, U32>)>();
// const MRT_LEN: usize = HMAC_OUTPUT_LEN + CTX_LEN + HMAC_OUTPUT_LEN + SIGMA_C_LEN;
const KF_LEN: usize = 32; // HMAC can be instantiated with variable size keys
const MRT_LEN: usize = 128 + CTX_LEN; // Hard-coding is less flexible, but this is empirically accurate.
// const RS_SIZE: usize = KF_LEN + MRT_LEN*N;

pub struct Client {
    pub uid: u32,
    pub k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    pub pks: Vec<PublicKey>, // Keys for servers along onion route
}

pub struct Moderator {
    pub sk: SecretKey,
    pub k_m: [u8; 32]
}

// Client operations

impl Client {
    pub fn new(k_r: Key<Aes256Gcm>, pks: Vec<PublicKey>) -> Client {
        Client {
            uid: rand::random(),
            k_r: k_r,
            pks: pks
        }
    }

    // Preprocessing is not possible in the optimized scheme
    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: &Vec<PublicKey>, n: usize) -> (Vec<u8>, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let rs_size = KF_LEN + MRT_LEN*n;
        let mut rs: Vec<u8> = vec![0; rs_size];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..KF_LEN];

        let c2 = com_commit(k_f, message);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, s)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let mut ct = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        for i in (0..n).rev() {
            let pk = &pks[i];
            let r_i = &rs[KF_LEN+i*MRT_LEN..KF_LEN+(i+1)*MRT_LEN];
            let payload = bincode::serialize(&(ct, r_i)).unwrap();
            ct = pk.seal(&mut rand_core::OsRng, &payload).unwrap();
        }

        (ct, c2)
    }

    // c2 is found inside st.
    pub fn read(k_r: Key<Aes256Gcm>, c1: Vec<u8>, st: Vec<u8>, n: usize) -> (String, String, (Vec<u8>, Vec<u8>), Vec<u8>) {

        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&k_r);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, [u8; 32])>(&payload_bytes).unwrap();

        let (m, s) = payload;

        let mut mrt = st;

        // Re-generate values from the seed s
        let rs_size = KF_LEN + MRT_LEN*n;
        let mut rs: Vec<u8> = vec![0; rs_size];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let k_f = &rs[0..KF_LEN];

        for i in 0..n {
            let r_i = &rs[KF_LEN+i*MRT_LEN..KF_LEN+(i+1)*MRT_LEN];
            mrt.iter_mut() // mrt = mrt XOR r_i
                .zip(r_i.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
        }

        let rt = bincode::deserialize::<(Vec<u8>, &str, Vec<u8>, Vec<u8>)>(&mrt).unwrap();

        let (c2, ctx, sigma, sigma_c) = rt;

        // Verify franking tag
        assert!(com_open(&c2, m, k_f));

        // Re-compute sigma_c to verify hash
        let mut hasher = sha3::Sha3_256::new();
        hasher.update([&sigma, &c2, ctx.as_bytes()].concat());
        let result = hasher.finalize().as_slice().to_vec();
        assert!(result == sigma_c);

        let rd = (k_f.to_vec(), c2);

        (m.to_string(), ctx.to_string(), rd, sigma)
    }
}

// Moderator operations

impl Moderator {
    pub fn mod_process(k_m: &[u8; 32], c2: &Vec<u8>, ctx: &str) -> (Vec<u8>, Vec<u8>) {
        let sigma = mac_sign(k_m, &[&c2, ctx.as_bytes()].concat());

        let mut hasher = sha3::Sha3_256::new();
        hasher.update([&sigma, c2, ctx.as_bytes()].concat());
        let sigma_c = hasher.finalize().as_slice().to_vec();

        (sigma, sigma_c)
    }

    pub fn moderate(k_m: &[u8; 32], m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let valid_f = com_open(&c2, m, &k_f);
        let valid_r = mac_verify(k_m, &[&c2, ctx.as_bytes()].concat(), sigma);

        valid_f && valid_r
    }

    pub fn new() -> Moderator {
        Moderator {
            sk: SecretKey::generate(&mut rand::rngs::OsRng),
            k_m: mac_keygen()
        }
    }

    pub fn get_pk(&self) -> PublicKey {
        self.sk.public_key()
    }
}

impl ServerCore for Moderator {}

pub struct Server {
    pub sk: SecretKey
}

// Server operations

impl Server {

    pub fn process(sk_i: &SecretKey, ct_i_minus_1: Vec<u8>, st_i_minus_1: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let payload = sk_i.unseal(&ct_i_minus_1).unwrap();
        let (ct_i, r_i) = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&payload).unwrap();

        let st_i: Vec<u8> = st_i_minus_1 // mrt_prime = mrt XOR ri
            .iter()
            .zip(r_i.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        (ct_i, st_i)
    }

    pub fn new() -> Server {
        let sk = SecretKey::generate(&mut rand::rngs::OsRng);
        Server {
            sk: sk
        }
    }

    pub fn get_pk(&self) -> PublicKey {
        self.sk.public_key()
    }
}