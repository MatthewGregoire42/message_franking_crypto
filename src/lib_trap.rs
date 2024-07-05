use rand::{Rng, SeedableRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand_core;
use bincode;
use sha3::Digest;
use crypto_box::{PublicKey, SecretKey};
// use generic_array::GenericArray;
// use typenum::consts::U32;
use crate::lib_common::*;

// const L: usize = 4; // Number of trap messages + 1 (so total # of tags sent)

// const SIGMA_C_LEN: usize = std::mem::size_of::<GenericArray<u8, U32>>();
// const MRT_LEN: usize = L*HMAC_OUTPUT_LEN + CTX_LEN + L*HMAC_OUTPUT_LEN + SIGMA_C_LEN;
const MRT_LEN: usize = CTX_LEN + 352;
const KF_LEN: usize = 32; // HMAC can be instantiated with variable size keys
// const RS_SIZE: usize = KF_LEN*L + MRT_LEN*N + 4; // An extra 4 bytes reserved for r_swap


pub struct Client {
    pub uid: u32,
    pub k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
    pub pks: Vec<PublicKey>, // Keys for servers along onion route
}

pub struct Moderator {
    pub sk: SecretKey,
    pub k_m: [u8; 32]
}

impl ServerCore for Moderator {}

fn as_usize_be(array: &[u8; 4]) -> usize {
    ((array[0] as usize) << 24) +
    ((array[1] as usize) << 16) +
    ((array[2] as usize) <<  8) +
    ((array[3] as usize) <<  0)
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

    pub fn send(message: &str, k_r: Key<Aes256Gcm>, pks: &Vec<PublicKey>, n: usize, ell: usize) -> (Vec<u8>, Vec<[u8; HMAC_OUTPUT_LEN]>, Vec<u8>) {
        let mut s: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut s);

        let rs_size = KF_LEN*ell + MRT_LEN*n + 4;
        let mut rs: Vec<u8> = vec![0; rs_size];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        // let kfs = &rs[0..L*KF_LEN];
        let r_swap = &rs[rs_size-4..];
        let swap = as_usize_be(r_swap.try_into().unwrap()) % ell;

        let mut c2: Vec<[u8; HMAC_OUTPUT_LEN]> = Vec::new();
 
        for i in 0..ell {
            let msg;
            if i == 0 {
                msg = message;
            } else {
                msg = "";
            }
            let kfi = &rs[i*KF_LEN..(i+1)*KF_LEN];
            c2.push(com_commit(kfi, msg).try_into().unwrap());
        }

        c2.swap(0, swap);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, s)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        let mut c3: Vec<u8> = Vec::new();
        for i in (0..n).rev() {
            let pk = &pks[i];
            let r_i = &rs[KF_LEN+i*MRT_LEN..KF_LEN+(i+1)*MRT_LEN];
            let payload = bincode::serialize(&(c3, r_i)).unwrap();
            c3 = pk.seal(&mut rand_core::OsRng, &payload).unwrap();
        }

        (c1, c2, c3)
    }

    // c2 is found inside st.
    pub fn read(&self, k_r: Key<Aes256Gcm>, c1: Vec<u8>, st: (Vec<u8>, Vec<u8>), n: usize, ell: usize) -> Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> {

        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&k_r);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, [u8; 32])>(&payload_bytes).unwrap();

        let (m, s) = payload;

        let mut mrt = st.1;

        // Re-generate values from the seed s
        let rs_size = KF_LEN*ell + MRT_LEN*n + 4;
        let mut rs: Vec<u8> = vec![0; rs_size];
        let mut g = rand::rngs::StdRng::from_seed(s);
        g.fill_bytes(&mut rs);

        let kfs = &rs[0..ell*KF_LEN];
        let r_swap = &rs[rs_size-4..];
        let swap = as_usize_be(r_swap.try_into().unwrap()) % ell;

        for i in 0..n {
            let r_i = &rs[KF_LEN+i*MRT_LEN..KF_LEN+(i+1)*MRT_LEN];
            mrt.iter_mut() // mrt = mrt XOR r_i
                .zip(r_i.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
        }

        let rt = bincode::deserialize::<(Vec<[u8; HMAC_OUTPUT_LEN]>, &str, Vec<Vec<u8>>, Vec<u8>)>(&mrt).unwrap();

        let (mut c2, ctx, mut sigma, sigma_c) = rt;

        // Re-compute sigma_c to verify hash
        let mut hasher = sha3::Sha3_256::new();
        for i in 0..ell {
            hasher.update([&sigma[i], &c2[i].to_vec(), ctx.as_bytes()].concat());
        }
        let result = hasher.finalize().as_slice().to_vec();
        assert!(result == sigma_c);

        // Undo the swap so we know that the message tag is in position 1
        c2.swap(0, swap);
        sigma.swap(0, swap);

        let mut reports: Vec<(String, String,(Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::new();

        // Verify all franking tags
        for i in 0..ell {
            let msg;
            if i == 0 {
                msg = m;
            } else {
                msg = "";
            }
            let kfi = &kfs[i*KF_LEN..(i+1)*KF_LEN];
            assert!(com_open(&c2[i].to_vec(), msg, &kfi));
            reports.push((msg.to_string(), ctx.to_string(), (kfi.to_vec(), c2[i].to_vec()), sigma[i].to_vec()));            
        }

        reports
    }
}

// Moderator operations

impl Moderator {
    pub fn mod_process(k_m: &[u8; 32], c2: &Vec<[u8; HMAC_OUTPUT_LEN]>, ctx: &str, ell: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut sigma: Vec<Vec<u8>> = Vec::new();

        for i in 0..ell {
            let sigma_i = mac_sign(k_m, &[&c2[i], ctx.as_bytes()].concat());
            sigma.push(sigma_i);
        }

        let mut hasher = sha3::Sha3_256::new();
        for i in 0..ell {
            hasher.update([&sigma[i], &c2[i].to_vec(), ctx.as_bytes()].concat());
        }
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