use rand::{Rng, SeedableRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha3::Digest;
use crypto_box::{PublicKey, SecretKey};
const N: usize = 3; // Number of servers

use crate::lib_common::*;

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    pks: Vec<PublicKey>, // Keys for servers along onion route
}

pub struct Moderator {
    sk: SecretKey,
    k_m: [u8; 32]
}

pub struct Server {
    sk: SecretKey
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

        let c2 = com_commit(k_f, message);

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

// Moderator operations

impl Moderator {
    pub fn mod_process(k_m: &[u8; 32], c2: Vec<u8>, ctx: &str) -> (Vec<u8>, Vec<u8>) {
        let sigma = mac_sign(k_m, &[&c2, ctx.as_bytes()].concat());

        let mut hasher = sha3::Sha3_256::new();
        hasher.update([&sigma, &c2, ctx.as_bytes()].concat());
        let sigma_c = hasher.finalize().as_slice().to_vec();

        (sigma, sigma_c)
    }

    pub fn moderate(k_m: &[u8; 32], m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let valid_f = com_open(&c2, m, &k_f);
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