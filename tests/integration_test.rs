extern crate zkp;
use message_franking_crypto::lib_common::*;
use message_franking_crypto::lib_common::{onion_peel, onion_encrypt};
use message_franking_crypto::lib_general as g;
use message_franking_crypto::lib_trap as t;
use message_franking_crypto::lib_comkey as c;
use message_franking_crypto::lib_optimized as o;
use message_franking_crypto::lib_plain as p;
use crypto_box::PublicKey;
use aes_gcm::{
    aead::KeyInit,
    Aes256Gcm
};

#[test]
fn test_general() {

     // Initialize servers
	let moderator = g::Moderator::new();

	let mut servers: Vec<Server> = Vec::with_capacity(9);
	let mut pks: Vec<PublicKey> = Vec::with_capacity(10);

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..10 {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

    // Sender
    let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

    let (s, rs, c3) = g::Client::send_preprocessing(&pks, 10);
    let (c1, c2) = g::Client::send_online("test message", k_r, s, rs);
    let mut ct = onion_encrypt(pks, c1);

    // Moderator
    let ctx = "message co";
    let (sigma, sigma_c) = g::Moderator::mod_process(&moderator.k_m, &c2, ctx);
    let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

    let mut st = (c3, mrt);
    st = Server::process(&moderator.sk, st);
    ct = onion_peel(&moderator.sk, ct.to_vec());

    // Other servers
    for i in 1..10 {
        println!("{}", i);
        st = Server::process(&servers[i-1].sk, st);
        ct = onion_peel(&servers[i-1].sk, ct.to_vec());
    }

    // Receiver
    let (m, ctx, rd, sigma) = g::Client::read(k_r, ct, st, 10);

    // Moderator
    let res = g::Moderator::moderate(&moderator.k_m, &m, &ctx, rd.clone(), sigma.clone());

    // Valid franking works
    assert!(res);

    let res = g::Moderator::moderate(&moderator.k_m, &m, "some other", rd, sigma);
    assert!(!res);
}

#[test]
fn test_comkey() {

    // Initialize servers
   let moderator = c::Moderator::new();

   let mut servers: Vec<Server> = Vec::with_capacity(9);
   let mut pks: Vec<PublicKey> = Vec::with_capacity(10);

   // Collect server public keys
   pks.push(moderator.get_pk());
   for i in 1..10 {
       let si = Server::new();
       servers.push(si);
       pks.push(servers[i-1].get_pk());
   }

   // Sender
   let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
   let receiver = c::Client::new(k_r, pks.clone(), moderator.sigma_k.compress());

   let (s, rs, c3) = c::Client::send_preprocessing(&pks, 10);
   let (c1, c2) = c::Client::send_online("test message", k_r, s, rs);
   let mut ct = onion_encrypt(pks, c1);

   // Moderator
   let ctx = "message co";
   let (sigma, sigma_c) = moderator.mod_process(&moderator.k_m, &c2, ctx);
   let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

   let mut st = (c3, mrt);
   st = Server::process(&moderator.sk, st);
   ct = onion_peel(&moderator.sk, ct.to_vec());

   // Other servers
   for i in 1..10 {
       println!("{}", i);
       st = Server::process(&servers[i-1].sk, st);
       ct = onion_peel(&servers[i-1].sk, ct.to_vec());
   }

   // Receiver
   let (m_prime, ctx_prime, rd_prime, sigma_prime) = receiver.read(k_r, ct, st, 10);

   assert_eq!("test message", m_prime);
   assert_eq!(ctx, ctx_prime);

   // Moderator
   let res = c::Moderator::moderate(&moderator.k_m, &m_prime, &ctx_prime, rd_prime.clone(), sigma_prime.clone());

   // Valid franking works
   assert!(res);

   let res = c::Moderator::moderate(&moderator.k_m, &m_prime, "some other", rd_prime, sigma_prime);
   assert!(!res);
}

#[test]
fn test_trap() {

    // Initialize servers
   let moderator = t::Moderator::new();

   let mut servers: Vec<Server> = Vec::with_capacity(9);
   let mut pks: Vec<PublicKey> = Vec::with_capacity(10);

   // Collect server public keys
   pks.push(moderator.get_pk());
   for i in 1..10 {
       let si = Server::new();
       servers.push(si);
       pks.push(servers[i-1].get_pk());
   }

   // Sender
   let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

   let (s, rs, c3) = t::Client::send_preprocessing(&pks, 10, 5);
   let (c1, c2) = t::Client::send_online("test message", k_r, s, rs, 10, 5);
   let mut ct = onion_encrypt(pks, c1);

   // Moderator
   let ctx = "message co";
   let (sigma, sigma_c) = t::Moderator::mod_process(&moderator.k_m, &c2, ctx, 5);
   let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

   let mut st = (c3, mrt);
   st = Server::process(&moderator.sk, st);
   ct = onion_peel(&moderator.sk, ct.to_vec());

   // Other servers
   for i in 1..10 {
       println!("{}", i);
       st = Server::process(&servers[i-1].sk, st);
       ct = onion_peel(&servers[i-1].sk, ct.to_vec());
   }

   // Receiver
   let reports = t::Client::read(k_r, ct, st, 10, 5);

   for i in 0..5 {
    let (m_prime, ctx_prime, rd_prime, sigma_prime) = reports[i].clone();

    if i == 0 {
        assert_eq!("test message", m_prime);
    } else {
        assert_eq!("", m_prime);
    }

    let res = t::Moderator::moderate(&moderator.k_m, &m_prime, &ctx_prime, rd_prime.clone(), sigma_prime.clone());

    assert!(res);

    let res = t::Moderator::moderate(&moderator.k_m, &m_prime, "some other", rd_prime, sigma_prime);
    assert!(!res);
   }
}

#[test]
fn test_optimized() {

    // Initialize servers
   let moderator = o::Moderator::new();

   let mut servers: Vec<Server> = Vec::with_capacity(9);
   let mut pks: Vec<PublicKey> = Vec::with_capacity(10);

   // Collect server public keys
   pks.push(moderator.get_pk());
   for i in 1..10 {
       let si = Server::new();
       servers.push(si);
       pks.push(servers[i-1].get_pk());
   }

   // Sender
   let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

   let (mut ct, c2) = o::Client::send("test message",k_r, &pks, 10);

   // Moderator
   let ctx = "message co";
   let (sigma, sigma_c) = o::Moderator::mod_process(&moderator.k_m, &c2, ctx);
   let mut mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

   (ct, mrt) = o::Server::process(&moderator.sk, ct, mrt);

   // Other servers
   for i in 1..10 {
       println!("{}", i);
       (ct, mrt) = o::Server::process(&servers[i-1].sk, ct, mrt);
   }

   // Receiver
   let (m_prime, ctx_prime, rd_prime, sigma_prime) = o::Client::read(k_r, ct, mrt, 10);

   assert_eq!("test message", m_prime);
   assert_eq!(ctx, ctx_prime);

   // Moderator
   let res = o::Moderator::moderate(&moderator.k_m, &m_prime, &ctx_prime, rd_prime.clone(), sigma_prime.clone());

   // Valid franking works
   assert!(res);

   let res = o::Moderator::moderate(&moderator.k_m, &m_prime, "some other", rd_prime, sigma_prime);
   assert!(!res);
}

#[test]
fn test_plain() {

     // Initialize servers
	let moderator = p::Moderator::new();

    // Sender
    let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

    let (c1, c2) = p::Client::send("test message", k_r);

    // Moderator
    let ctx = "message co";
    let sigma = p::Moderator::mod_process(&moderator.k_m, &c2, ctx);

    // Receiver
    let (m_prime, ctx_prime, rd_prime, sigma_prime) = 
        p::Client::read(k_r, c1, (c2, ctx.to_string(), sigma));

    assert_eq!("test message", m_prime);
    assert_eq!(ctx, ctx_prime);

    // Moderator
    let res = p::Moderator::moderate(&moderator.k_m, &m_prime, &ctx_prime, rd_prime.clone(), sigma_prime.clone());

    // Valid franking works
    assert!(res);

    let res = p::Moderator::moderate(&moderator.k_m, &m_prime, "some other", rd_prime, sigma_prime);
    assert!(!res);
}