#[macro_use]
extern crate zkp;
use lib_common::onion_encrypt;
use message_franking_crypto::lib_common::*;
use crate::lib_common::onion_peel;
use message_franking_crypto::lib_general as g;
use message_franking_crypto::lib_trap as t;
use message_franking_crypto::lib_comkey as c;
use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};

pub mod lib_common;
pub mod lib_general;
pub mod lib_trap;
pub mod lib_comkey;
// mod lib_optimized;

fn main() {
	println!("Hello, World!");

	// General scheme

	// Initialize servers
	let moderator = g::Moderator::new();

	let mut servers: Vec<Server> = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..N {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);

	let sender = g::Client::new(k_r, pks.clone());

	let receiver = g::Client::new(k_r, pks.clone());

	// Send a message!
	let m = "test message";

	// Sender
	let (c1, c2, c3) = g::Client::send(m, sender.k_r, &pks);
	let mut ct = onion_encrypt(pks, c1);

	// Moderator
	let ctx = "10char str";
	let (sigma, sigma_c) = g::Moderator::mod_process(&moderator.k_m, &c2, ctx);
	let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();
	let mut st = (c3, mrt);
	st = Server::process(&moderator.sk, st);
	ct = onion_peel(&moderator.sk, ct);

	// Other servers
	for i in 1..N {
		let si = &servers[i-1];
		st = Server::process(&si.sk, st);
		ct = onion_peel(&si.sk, ct);
	}

	// Receiver
	let (m, ctx, rd, sigma) = g::Client::read(k_r, ct, st);

	// Reporting back to moderator
	let res = g::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);

	if res {
		println!("Report success!");
	} else {
		println!("Report failed");
	}
	
}