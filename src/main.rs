#[macro_use]
extern crate zkp;
use message_franking_crypto::lib_common::*;
use message_franking_crypto::lib_general as g;
use message_franking_crypto::lib_trap as t;
use message_franking_crypto::lib_comkey as c;
use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;

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

	pks.push(moderator.get_pk());
	for i in 1..N {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
	let sender = g::Client::new(pks.clone());
}