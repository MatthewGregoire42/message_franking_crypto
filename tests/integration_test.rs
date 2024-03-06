use message_franking_crypto::franking::*;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::prelude::*;
use generic_array::GenericArray;
use rand_chacha::ChaCha8Rng;
use hmac::{Hmac, Mac, NewMac};
use rand_chacha::rand_core::SeedableRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key
};
use sha2::{Sha256, Digest};


#[test]
fn send_reencrypt() {
    let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
    thread_rng().fill(&mut seed);
    let rng = ChaCha8Rng::from_seed(seed);
    let k_r = Aes256Gcm::generate_key(rng);
    let cipher = Aes256Gcm::new(&k_r);

    // Create Server PK
    let mut rng_el = rand::thread_rng();
    let x = Scalar::random(&mut rng_el);
    let g: &RistrettoPoint = &GEN_G;
    let pk = g * x;

    // Server PK is the same as moderator PK in this case 
    let pk_m = pk.clone();

    // Call send_reencrypt
    let ((c1, c2), (c1_m, c2_m)) = Client::send_reencrypt("Hello, World!", k_r, pk, pk_m);

    // Decrypt the first ciphertext and ensure that everything is ok:
    let s = c1 * x;
    let mut hasher1 = Sha256::new();
    hasher1.update(s.compress().to_bytes());
    let mut hash_s: Vec<u8> = hasher1.clone().finalize().to_vec();
    let zero_vec = vec![0; c2.len() - 32];
    hash_s.extend(zero_vec);
    let ct: Vec<u8> = c2
            .iter()
            .zip(hash_s.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    let nonce: &GenericArray<u8, aes_gcm::aead::consts::U12> = GenericArray::from_slice(&ct[0..12]);
    let plaintext_pkg = cipher.decrypt(nonce, &ct[12..]).unwrap();
    let plainttext: MessagePackage = bincode::deserialize(&plaintext_pkg).unwrap();

    assert_eq!(plainttext.m, "Hello, World!");

    // Decrypt the second ciphertext and ensure that everything is ok: 
    let s = c1_m * x;
    let mut hasher2 = hasher1.clone();
    hasher2.update(s.compress().to_bytes());
    let mut hash_s: Vec<u8> = hasher2.finalize().to_vec();
    let zero_vec = vec![0; c2.len() - 32];
    hash_s.extend(zero_vec);
    let k_tf: Vec<u8> = c2_m
            .iter()
            .zip(hash_s.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    let mod_package: ModeratorPackage = bincode::deserialize(&k_tf).unwrap();

    assert_eq!(plainttext.tf, mod_package.tf);
}

#[test]
fn receive_reencrypt_rejects_incorrect_message() {

    let message = "Hello, World!";
    // Choose random seed s and seed the RNG
    // ====================================================================
    let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
    thread_rng().fill(&mut seed);
    let mut rng = ChaCha8Rng::from_seed(seed);
    // ====================================================================

    // Generate moderator key k and receiver key k_r
    // ====================================================================
    let k = Aes256Gcm::generate_key(&mut rng);
    let k_r = Aes256Gcm::generate_key(&mut rng);
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
    let zero_vec = vec![0; 32];
    let msg_package = MessagePackage {
        m: message,
        kf: mackey_kf,
        tf: zero_vec.clone(),
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


    // Encrypt tf, tr, ctxt under k using AES-GCM
    // ====================================================================
    let rep_package = ReceiverReportPackage {
        tr: zero_vec.clone(),
        tf: zero_vec.clone(),
        ctxt: zero_vec.clone(),
    };
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&bincode::serialize(&rep_package).unwrap());
    let cipher = Aes256Gcm::new(&k);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();
    let mut ct_rep: Vec<u8> = Vec::new();
    ct_rep.extend_from_slice(&nonce);
    ct_rep.extend_from_slice(&ciphertext);   
    // ====================================================================

    let plainttext = Client::receive_reencrypt(k_r, ct, ct_rep);
    assert!(plainttext.is_err());
}

#[test]
fn receive_reencrypt_decrypts_correct_message() {

    let message = "Hello, World!";
    // Choose random seed s and seed the RNG
    // ====================================================================
    let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
    thread_rng().fill(&mut seed);
    let mut rng = ChaCha8Rng::from_seed(seed);
    // ====================================================================

    // Generate moderator key k and receiver key k_r
    // ====================================================================
    let k = Aes256Gcm::generate_key(&mut rng);
    let k_r = Aes256Gcm::generate_key(&mut rng);
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


    // Encrypt tf, tr, ctxt under k using AES-GCM
    // ====================================================================
    let zero_vec = vec![0; 32];
    let rep_package = ReceiverReportPackage {
        tr: zero_vec.clone(),
        tf: franktag_tf.to_vec(),
        ctxt: zero_vec.clone(),
    };
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&bincode::serialize(&rep_package).unwrap());
    let cipher = Aes256Gcm::new(&k);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();
    let mut ct_rep: Vec<u8> = Vec::new();
    ct_rep.extend_from_slice(&nonce);
    ct_rep.extend_from_slice(&ciphertext);   
    // ====================================================================

    let plainttext = Client::receive_reencrypt(k_r, ct, ct_rep);
    assert!(plainttext.is_ok());
    assert_eq!(plainttext.unwrap().m, String::from(message));
}
