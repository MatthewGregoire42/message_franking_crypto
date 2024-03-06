use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use rand::prelude::*;
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use lazy_static::lazy_static;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key
};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Sha256, Digest};


lazy_static! {
    pub static ref GEN_G: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

pub struct Client {
    uid: u32,
    k_r: Key<Aes256Gcm>, // The client's receiver key
}

#[derive(Serialize, Deserialize)]
pub struct MessagePackage<'a> {
    pub m: &'a str,
    pub kf: [u8; 32],
    pub tf: Vec<u8>,
    pub s: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ReceiverReportPackage {
    pub tr: Vec<u8>,
    pub tf: Vec<u8>,
    pub ctxt: Vec<u8>,
}
<<<<<<< HEAD

#[derive(Serialize, Deserialize)]
pub struct ModeratorReportPackage {
    pub m: String,
    pub tr: Vec<u8>,
    pub tf: Vec<u8>,
    pub ctxt: Vec<u8>,
    pub kf: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ModeratorPackage {
    pub k: Vec<u8>,
    pub tf: Vec<u8>,
}

impl Client {

    pub fn send_reencrypt(message: &str, k_r: Key<Aes256Gcm>, pk: RistrettoPoint, pk_m: RistrettoPoint) -> ((RistrettoPoint, Vec<u8>), (RistrettoPoint, Vec<u8>)) {

        // Input: message, public keys, receiver's symmetric key
        // Output: 2 El Gamal Ciphertexts (1 containing encrypted message/franking information, 1 for the moderator)

        // Choose random seed s and seed the RNG
        // ====================================================================
        let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
        thread_rng().fill(&mut seed);
        let mut rng = ChaCha8Rng::from_seed(seed);
        // ====================================================================

        // Generate moderator key k
        // ====================================================================
        let k = Aes256Gcm::generate_key(&mut rng);
        // ====================================================================

        // Generate ephemeral MAC key kf
        // ====================================================================
        type HmacSha256 = Hmac<Sha256>;
        let mackey_kf = thread_rng().gen::<[u8; 32]>();
        // ====================================================================

        // Compute franking tag tf 
        // ====================================================================
        let mut mac = HmacSha256::new_varkey(&mackey_kf).expect("HMAC");
        let macinput: &[u8] = message.as_bytes();
        mac.update(macinput);
        let franktag_tf = (mac.finalize()).into_bytes();
        // ====================================================================

        // Encrypt m, kf, tf, s --> ct using AES-GCM
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
        let g: &RistrettoPoint = &GEN_G;
        let h: &RistrettoPoint = &pk;
        let mut rng_el = rand::thread_rng();
        let y = Scalar::random(&mut rng_el);
        let s = h * y;
        let c1 = g * y;
        // Rather than multiplying the message with s, we instead hash s and XOR the message
        // with the result. This prevents us from having to map messages to RistrettoPoints 
        // in an invertible way, since that doesn't seem to be doable with this crate (TOOD: is
        // that correct?)
        let mut hasher1 = Sha256::new();
        hasher1.update(s.compress().to_bytes());
        let mut hash_s: Vec<u8> = hasher1.clone().finalize().to_vec();
        let zero_vec = vec![0; ct.len() - 32];
        hash_s.extend(zero_vec);
        let c2: Vec<u8> = ct
                .iter()
                .zip(hash_s.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
        // ====================================================================

        // Encrypt k and tf under moderator public key (Hashed El Gamal again)
        // ====================================================================
        let h: &RistrettoPoint = &pk_m;
        let y = Scalar::random(&mut rng_el);
        let s = h * y;
        let c1_m = g * y;
        let mut hasher2 = hasher1.clone();
        hasher2.update(s.compress().to_bytes());
        let mut hash_s: Vec<u8> = hasher2.finalize().to_vec();

        let mod_package = ModeratorPackage {
            k: k.to_vec(),
            tf: franktag_tf.to_vec(),
        };
        let mut k_tf: Vec<u8> = Vec::new();
        k_tf.extend_from_slice(&bincode::serialize(&mod_package).unwrap());
        let zero_vec = vec![0; k_tf.len() - 32];
        hash_s.extend(zero_vec);
        let c2_m: Vec<u8> = k_tf
                .iter()
                .zip(hash_s.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
        // ====================================================================
        return ((c1, c2), (c1_m, c2_m));

    }
    pub fn receive_reencrypt(k_r: Key<Aes256Gcm>, ct: Vec<u8>, ct_report: Vec<u8>) -> Result<ModeratorReportPackage, &'static str> {

        // Input: ct (symmetric under k) and (t_r, t_f, ctxt) encrypted symmetrically under k

        // Decrypt ct with k_r to obtain a MessagePackage
        // ====================================================================
        let cipher_ct = Aes256Gcm::new(&k_r);
        let nonce: &GenericArray<u8, aes_gcm::aead::consts::U12> = GenericArray::from_slice(&ct[0..12]);
        let decryption = cipher_ct.decrypt(nonce, &ct[12..]).unwrap();
        let msg_package: MessagePackage = bincode::deserialize(&decryption).unwrap();
        // ====================================================================

        // Decrypt (t_r, t_f, ctxt) to obtain a ReceiverReportPackage
        // ====================================================================
        let mut rng = ChaCha8Rng::from_seed(msg_package.s);
        let k = Aes256Gcm::generate_key(&mut rng);
        let cipher_rep = Aes256Gcm::new(&k);
        let nonce: &GenericArray<u8, aes_gcm::aead::consts::U12> = GenericArray::from_slice(&ct_report[0..12]);
        let decryption = cipher_rep.decrypt(nonce, &ct_report[12..]).unwrap();
        let rep_package: ReceiverReportPackage = bincode::deserialize(&decryption).unwrap();
        // ====================================================================

        // Verify that t_f was computed correctly
        // ====================================================================
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_varkey(&msg_package.kf).expect("HMAC");
        let macinput: &[u8] = msg_package.m.as_bytes();
        mac.update(macinput);
        let result = mac.verify(&msg_package.tf[..]);
        if result.is_err() {
            return Err("Franking Tag MAC did not verify"); // Reject the message
        }
        // ====================================================================

        // Verify that t_f in the msg_package and the rep_package match
        // ====================================================================
        if msg_package.tf != rep_package.tf { 
            return Err("Franking Tags did not match"); 
        }
        // ====================================================================
        let mod_rep_package = ModeratorReportPackage {
            m: String::from(msg_package.m),
            tr: rep_package.tr.clone(),
            tf: msg_package.tf.clone(),
            ctxt: rep_package.ctxt.clone(),
            kf: msg_package.kf.clone(),
        };

        return Ok(mod_rep_package);

    }
    // pub fn report(pkg: Rep) {

    //     // TODO

    // }
}
