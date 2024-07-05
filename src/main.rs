#[macro_use]
extern crate zkp;
use lib_common::onion_encrypt;
use message_franking_crypto::lib_common::*;
use crate::lib_common::onion_peel;
use message_franking_crypto::lib_general as g;
use message_franking_crypto::lib_trap as t;
use message_franking_crypto::lib_comkey as c;
use message_franking_crypto::lib_optimized as o;
use crypto_box::PublicKey;
use aes_gcm::{
    aead::KeyInit,
    Aes256Gcm
};
use std::time::Instant;

pub mod lib_common;
pub mod lib_general;
pub mod lib_trap;
pub mod lib_comkey;
mod lib_optimized;

fn main() {
	println!("Hello, World!");

    test_general(3);
    test_trap(3, 2);
    test_trap(3, 3);
    test_trap(3, 4);
    test_trap(3, 5);
    test_trap(4, 4);
    test_comkey(3);
    test_optimized(3);
}

// --------------------
// General scheme
// --------------------
fn test_general(n: usize) {
    // Initialize servers
	let moderator = g::Moderator::new();

	let mut servers: Vec<Server> = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

	let sender = g::Client::new(k_r, pks.clone());

	// Send a message!
	let m = "test message";

	// Sender
	let (c1, c2, c3) = g::Client::send(m, sender.k_r, &pks, n);
	let mut ct = onion_encrypt(pks, c1);

	// Moderator
	let ctx = "10char str";
	let (sigma, sigma_c) = g::Moderator::mod_process(&moderator.k_m, &c2, ctx);
	let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();
    println!("mrt size general: {:?}", mrt.len());
	let mut st = (c3, mrt);
	st = Server::process(&moderator.sk, st);
	ct = onion_peel(&moderator.sk, ct);

	// Other servers
	for i in 1..n {
		let si = &servers[i-1];
		st = Server::process(&si.sk, st);
		ct = onion_peel(&si.sk, ct);
	}

	// Receiver
	let (m, ctx, rd, sigma) = g::Client::read(k_r, ct, st, n);

	// Reporting back to moderator
	let res = g::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);

	if res {
		println!("Report success!");
	} else {
		println!("Report failed");
	}
}

// --------------------
// Trap message scheme
// --------------------
fn test_trap(n: usize, ell: usize) {
    // Initialize servers
	let moderator = t::Moderator::new();

	let mut servers: Vec<Server> = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

	let sender = t::Client::new(k_r, pks.clone());

	let receiver = t::Client::new(k_r, pks.clone());

	// Send a message!
	let m = "test message";

	// Sender
	let (c1, c2, c3) = t::Client::send(m, sender.k_r, &pks, n, ell);
	let mut ct = onion_encrypt(pks, c1);

	// Moderator
	let ctx = "10char str";
	let (sigma, sigma_c) = t::Moderator::mod_process(&moderator.k_m, &c2, ctx, ell);
	let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();
    println!("ell: {}, mrt size: {}", ell, mrt.len());
    println!("mrt size trap: {:?}", mrt.len());
	let mut st = (c3, mrt.clone());
    // println!("Initial mrt: {:?}", mrt);
	st = Server::process(&moderator.sk, st);
	ct = onion_peel(&moderator.sk, ct);

	// Other servers
	for i in 1..n {
		let si = &servers[i-1];
		st = Server::process(&si.sk, st);
		ct = onion_peel(&si.sk, ct);
	}

	// Receiver
	let reports = receiver.read(k_r, ct, st, n, ell);

    for i in 0..reports.len() {
        let (m, ctx, rd, sigma) = &reports[i];
        // Reporting back to moderator
        let res = t::Moderator::moderate(&moderator.k_m, &m, &ctx, rd.clone(), sigma.to_vec());

        if res {
            println!("Report success!");
        } else {
            println!("Report failed");
        }   
    }  
}

// --------------------
// Committed key scheme
// --------------------
fn test_comkey(n: usize) {
    // Initialize servers
	let moderator = c::Moderator::new();
    let sigma_k = moderator.sigma_k.compress();

	let mut servers: Vec<Server> = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

	let sender = c::Client::new(k_r, pks.clone(), sigma_k);

	let receiver = c::Client::new(k_r, pks.clone(), sigma_k);

	// Send a message!
	let m = "test message";

	// Sender
	let (c1, c2, c3) = c::Client::send(m, sender.k_r, &pks, n);
	let mut ct = onion_encrypt(pks, c1);

	// Moderator
	let ctx = "10char str";
	let (sigma, pi) = moderator.mod_process(&moderator.k_m, &c2, ctx);
	let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, pi)).unwrap();
    println!("mrt size comkey: {:?}", mrt.len());
	let mut st = (c3, mrt.clone());
    // println!("Initial mrt: {:?}", mrt);
	st = Server::process(&moderator.sk, st);
	ct = onion_peel(&moderator.sk, ct);

	// Other servers
	for i in 1..n {
		let si = &servers[i-1];
		st = Server::process(&si.sk, st);
		ct = onion_peel(&si.sk, ct);
	}

	// Receiver
	let (m, ctx, rd, sigma) = receiver.read(k_r, ct, st, n);

	// Reporting back to moderator
	let res = c::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);

	if res {
		println!("Report success!");
	} else {
		println!("Report failed");
	}     
}

// --------------------
// Optimized scheme
// --------------------
fn test_optimized(n: usize) {
    // Initialize servers
	let moderator = o::Moderator::new();

	let mut servers: Vec<o::Server> = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = o::Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

	let sender = o::Client::new(k_r, pks.clone());

	let receiver = o::Client::new(k_r, pks.clone());

	// Send a message!
	let m = "test message";

	// Sender
	let (mut ct, c2) = o::Client::send(m, sender.k_r, &pks, n);

	// Moderator
	let ctx = "10char str";
	let (sigma, sigma_c) = o::Moderator::mod_process(&moderator.k_m, &c2, ctx);
	let mut st = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();
    println!("mrt size optimized: {:?}", st.len());
	(ct, st) = o::Server::process(&moderator.sk, ct, st);

	// Other servers
	for i in 1..n {
		let si = &servers[i-1];
		(ct, st) = o::Server::process(&si.sk, ct, st);
	}

	// Receiver
	let (m, ctx, rd, sigma) = o::Client::read(k_r, ct, st, n);

	// Reporting back to moderator
	let res = o::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);

	if res {
		println!("Report success!");
	} else {
		println!("Report failed");
	}
}