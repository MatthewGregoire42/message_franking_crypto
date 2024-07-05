extern crate zkp;
use message_franking_crypto::lib_common::*;
use message_franking_crypto::lib_common::{onion_peel, onion_encrypt};
use message_franking_crypto::lib_general as g;
use message_franking_crypto::lib_trap as t;
use message_franking_crypto::lib_comkey as c;
use message_franking_crypto::lib_optimized as o;
use crypto_box::PublicKey;
use aes_gcm::{
    aead::KeyInit,
    Aes256Gcm
};
use rand::distributions::DistString;
use rand::distributions::Alphanumeric;
use std::time::{Instant, Duration};

const N: usize = 20; // Number of trials to average each operation over

pub fn main() {
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
pub fn test_general(n: usize) -> (Duration, Duration, Duration, Duration, Duration) {
    // Initialize servers
	let moderator = g::Moderator::new();

	let mut servers: Vec<Server> = Vec::with_capacity(n);
	let mut pks: Vec<PublicKey> = Vec::with_capacity(n);

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
    let mut senders: Vec<g::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = g::Client::new(k_r, pks.clone());
        senders.push(sender);
    }

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), 20);
        ms.push(m);
    }

	// Sender
    let mut c1c2c3s: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let now = Instant::now();
    for i in 0..N {
        let (c1, c2, c3) = g::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2c3s.push((c1, c2, c3));
    }
    let t_send = now.elapsed();

    let mut cts: Vec<Vec<u8>> = Vec::with_capacity(N);
    for i in 0..N {
        let c1 = c1c2c3s[i].0.clone();
        let ct = onion_encrypt(pks.clone(), c1);
        cts.push(ct);
    }

	// Moderator
    let mut ctxs: Vec<String> = Vec::with_capacity(N);
    let mut sigmas: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut sigma_cs: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut mrts: Vec<Vec<u8>> = Vec::with_capacity(N);
    let now = Instant::now();
    for i in 0..N {
        let (_, c2, _) = c1c2c3s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

        let (sigma, sigma_c) = g::Moderator::mod_process(&moderator.k_m, &c2, &ctx);
        sigmas.push(sigma.clone());
        sigma_cs.push(sigma_c.clone());

        let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

        mrts.push(mrt);
    }
    let t_mod_process = now.elapsed();

    let mut sts: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let now = Instant::now();
    for i in 0..N {
        let (_, _, c3) = c1c2c3s[i].clone();
        let mrt = mrts[i].clone();

        let mut st = (c3, mrt);
        st = Server::process(&moderator.sk, st);
        sts.push(st.clone());
    }
    let mut t_process = now.elapsed();

    println!("mrt size general: {:?}", sts[0].1.len());

    for i in 0..N {
        let ct = cts[i].clone();
        cts[i] = onion_peel(&moderator.sk, ct);
    }

	// Other servers
    let now = Instant::now();
    for i in 0..N {
        let mut st = sts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
            st = Server::process(&sj.sk, st.clone());
        }
        sts[i] = st;
    }
    t_process = t_process + now.elapsed();

    for i in 0..N {
        let mut ct = cts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
            ct = onion_peel(&sj.sk, ct.to_vec());
        }
        cts[i] = ct;
    }

	// Receiver
    let mut reports: Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::with_capacity(N);
    let now = Instant::now();
    for i in 0..N {
        let k_r = senders[i].k_r;
        let ct = cts[i].clone();
        let st = sts[i].clone();
	    let (m, ctx, rd, sigma) = g::Client::read(k_r, ct, st, n);
        reports.push((m, ctx, rd, sigma));
    }
    let t_read = now.elapsed();

	// Reporting back to moderator
    let now = Instant::now();
    for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
        let res = g::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
        if !res {
            panic!("Report failed");
        }
    }
    let t_moderate = now.elapsed();

    (t_send, t_mod_process, t_process, t_read, t_moderate)
}

// --------------------
// Trap message scheme
// --------------------
pub fn test_trap(n: usize, ell: usize) {
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
pub fn test_comkey(n: usize) {
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
pub fn test_optimized(n: usize) {
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