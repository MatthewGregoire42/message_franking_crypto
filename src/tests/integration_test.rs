use message_franking_crypto::franking::*;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::prelude::*;
use generic_array::GenericArray;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
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