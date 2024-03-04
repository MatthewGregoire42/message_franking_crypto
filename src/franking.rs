use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::prelude::*;
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Sha256, Digest};

/*
    1. use curve25519 for elgamal implementation
    2. implement:
        - Client:
            * send msg
            * receive msg
            * report msg
        - Moderator:
            * receive and pass along msg
        - Server:
            * receive and pass along msg

        These three are all different in reencryption vs decryption settings
*/

lazy_static! {
    pub static ref GEN_G: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

pub struct Client {
    uid: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MessagePackage<'a> {
    pub m: &'a str,
    pub kf: [u8; 32],
    pub tf: Vec<u8>,
    pub s: [u8; 32],
}

impl Client {

    pub fn send_reencrypt(message: &str, k_r: Key<Aes256Gcm>, pk: RistrettoPoint) -> (RistrettoPoint, Vec<u8>) {

        // Input: message, public keys, receiver's symmetric key
        // Output: 2 El Gamal Ciphertexts (1 containing encrypted message/franking information, 1 for the moderator)

        // Choose random seed s
        // ====================================================================
        let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
        thread_rng().fill(&mut seed);
        let mut rng = ChaCha8Rng::from_seed(seed);
        // ====================================================================

        // Generate ephemeral MAC key kf
        // ====================================================================
        type HmacSha256 = Hmac<Sha256>;
        let mackey_kf = thread_rng().gen::<[u8; 32]>();
        // ====================================================================

        // Compute franking tag tf 
        // ====================================================================
        let mut mac = HmacSha256::new_varkey(&mackey_kf).expect("HMAC");
        let mut macinput: &[u8] = message.as_bytes();
        mac.update(macinput);
        let franktag_tf = (mac.finalize()).into_bytes();
        // ====================================================================

        // Encrypt m, kf, tf, s --> ct 
        // ====================================================================
        let msg_package = MessagePackage {
            m: message,
            kf: mackey_kf,
            tf: franktag_tf.to_vec(),
            s: seed,
        };
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&bincode::serialize(&msg_package).unwrap());
        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();
        let mut ct: Vec<u8> = Vec::new();
        ct.extend_from_slice(&nonce);
        ct.extend_from_slice(&ciphertext);
        // ====================================================================

        // Encrypt ct under public key into ct' (using Hashed El Gamal)
        // ====================================================================
        let G: &RistrettoPoint = &GEN_G;
        let H: &RistrettoPoint = &pk;
        let mut rng_el = rand::thread_rng();
        let y = Scalar::random(&mut rng_el);
        let s = H * y;
        let c1 = G * y;
        // Rather than multiplying the message with s, we instead hash s and XOR the message
        // with the result. This prevents us from having to map messages to RistrettoPoints 
        // in an invertible way, since that doesn't seem to be doable with this crate (TOOD: is
        // that correct?)
        let mut hasher = Sha256::new();
        hasher.update(s.compress().to_bytes());
        let mut hash_s: Vec<u8> = hasher.finalize().to_vec();
        let zero_vec = vec![0; ct.len() - 32];
        hash_s.extend(zero_vec);
        let c2: Vec<u8> = ct
			    .iter()
			    .zip(hash_s.iter())
			    .map(|(&x1, &x2)| x1 ^ x2)
			    .collect();
        // ====================================================================
        return (c1, c2);


        // TODO: Encrypt k and tf under moderator public key (el gamal)
    }
    pub fn receive_reencrypt(&mut self, message: &str) {

        // TODO

    }
    pub fn report_reencrypt(&mut self, message: &str) {

        // TODO

    }
}
