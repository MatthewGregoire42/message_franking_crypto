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
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm};
use rand::distributions::DistString;
use rand::distributions::Alphanumeric;
use std::time::{Instant, Duration};

const N: usize = 1000; // Number of trials to average each operation over
const MAX_N_SERVERS: usize = 10; // Test all numbers of servers from 2 to...
const MAX_N_TRAPS: usize = 5; // Test all numbers of trap messages from 1 to...

pub fn main() {
    println!("All times are reported in nanoseconds.");
    println!("Scheme    Servers   Msg size  Send (offln)   Send (onln)    ModProcess     Process        Read           Moderate       c3 bytes  st bytes  rep bytes Traps");
    for msg_size in (0..1001).step_by(100) {
        for n_servers in 2..MAX_N_SERVERS+1 {
            let (t_send_offline, t_send_online, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size) = test_general(n_servers, msg_size);
            let res = format!("{: <10}{: <10}{: <10}{: <15}{: <15}{: <15}{: <15}{: <15}{: <15}{: <10}{: <10}{: <10}-",
                "General", n_servers, msg_size,
                t_send_offline.div_f32(N as f32).as_nanos(),
                t_send_online.div_f32(N as f32).as_nanos(),
                t_mod_process.div_f32(N as f32).as_nanos(),
                t_process.div_f32(N as f32).as_nanos(),
                t_read.div_f32(N as f32).as_nanos(),
                t_moderate.div_f32(N as f32).as_nanos(),
                c3_size, mrt_size, rep_size);
            println!("{}", res);
        }

        for n_servers in 2..MAX_N_SERVERS+1 {
            for n_traps in 1..(MAX_N_TRAPS+1) {
                let (t_send_offln, t_send_onln, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size) = test_trap(n_servers, n_traps+1, msg_size);
                let res = format!("{: <10}{: <10}{: <10}{: <15}{: <15}{: <15}{: <15}{: <15}{: <15}{: <10}{: <10}{: <10}{}",
                    "Trap", n_servers, msg_size,
                    t_send_offln.div_f32(N as f32).as_nanos(),
                    t_send_onln.div_f32(N as f32).as_nanos(),
                    t_mod_process.div_f32(N as f32).as_nanos(),
                    t_process.div_f32(N as f32).as_nanos(),
                    t_read.div_f32(N as f32).as_nanos(),
                    t_moderate.div_f32(N as f32).as_nanos(),
                    c3_size, mrt_size, rep_size, n_traps);
                println!("{}", res);
            }
        }

        for n_servers in 2..MAX_N_SERVERS+1 {
            let (t_send_offln, t_send_onln, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size) = test_comkey(n_servers, msg_size);
            let res = format!("{: <10}{: <10}{: <10}{: <15}{: <15}{: <15}{: <15}{: <15}{: <15}{: <10}{: <10}{: <10}-",
                "Comkey", n_servers, msg_size,
                t_send_offln.div_f32(N as f32).as_nanos(),
                t_send_onln.div_f32(N as f32).as_nanos(),
                t_mod_process.div_f32(N as f32).as_nanos(),
                t_process.div_f32(N as f32).as_nanos(),
                t_read.div_f32(N as f32).as_nanos(),
                t_moderate.div_f32(N as f32).as_nanos(),
                c3_size, mrt_size, rep_size);
            println!("{}", res);
        }

        for n_servers in 2..MAX_N_SERVERS+1 {
            let (t_send, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size) = test_optimized(n_servers, msg_size);
            let res = format!("{: <10}{: <10}{: <10}-              {: <15}{: <15}{: <15}{: <15}{: <15}{: <10}{: <10}{: <10}-",
                "Optimized", n_servers, msg_size,
                t_send.div_f32(N as f32).as_nanos(),
                t_mod_process.div_f32(N as f32).as_nanos(),
                t_process.div_f32(N as f32).as_nanos(),
                t_read.div_f32(N as f32).as_nanos(),
                t_moderate.div_f32(N as f32).as_nanos(),
                c3_size, mrt_size, rep_size);
            println!("{}", res);
        }

		let (t_send, t_mod_process, t_read, t_moderate, send_size, rep_size) = test_plain(msg_size);
		let res = format!("{: <10}-         {: <10}-              {: <15}{: <15}-              {: <15}{: <15}{: <10}-         {: <10}-",
			"Plain", msg_size,
			t_send.div_f32(N as f32).as_nanos(),
			t_mod_process.div_f32(N as f32).as_nanos(),
			t_read.div_f32(N as f32).as_nanos(),
			t_moderate.div_f32(N as f32).as_nanos(),
			send_size, rep_size);
		println!("{}", res);
    }

}

// --------------------
// General scheme
// --------------------
pub fn test_general(n: usize, msg_size: usize) -> (Duration, Duration, Duration, Duration, Duration, Duration, usize, usize, usize) {
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
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut c1c2c3s: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let mut t_send_offln = Duration::ZERO;
    let mut t_send_onln = Duration::ZERO;
    for i in 0..N {
        let now = Instant::now();
        let (s, rs, c3) = g::Client::send_preprocessing(&pks, n);
        t_send_offln += now.elapsed();

        let now = Instant::now();
        let (c1, c2) = g::Client::send_online(&ms[i], senders[i].k_r, s, rs);
        t_send_onln += now.elapsed();

        // Not bundling offline and online
        // let (c1, c2, c3) = g::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2c3s.push((c1, c2, c3));
    }

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
	let mut t_mod_process = Duration::ZERO;
    for i in 0..N {
        let (_, c2, _) = c1c2c3s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

		let now = Instant::now();
        let (sigma, sigma_c) = g::Moderator::mod_process(&moderator.k_m, &c2, &ctx);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());
        sigma_cs.push(sigma_c.clone());

        let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

        mrts.push(mrt);
    }
    let c3_size = c1c2c3s[0].2.len();

    let mut sts: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
	let mut t_process = Duration::ZERO;
	for i in 0..N {
        let (_, _, c3) = c1c2c3s[i].clone();
        let mrt = mrts[i].clone();

        let mut st = (c3, mrt);
		let now = Instant::now();
        st = Server::process(&moderator.sk, st);
		t_process += now.elapsed();
        sts.push(st.clone());
    }

    let mrt_size = sts[0].1.len();

    for i in 0..N {
        let ct = cts[i].clone();
        cts[i] = onion_peel(&moderator.sk, ct);
    }

	// Other servers
    
    for i in 0..N {
        let mut st = sts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
			let now = Instant::now();
            st = Server::process(&sj.sk, st.clone());
			t_process += now.elapsed();
        }
        sts[i] = st;
    }
    t_process = t_process.div_f32(n as f32); // We did (# trials)*(# servers) processes, so divide out (# servers)

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
	let mut t_read = Duration::ZERO;
    for i in 0..N {
        let k_r = senders[i].k_r;
        let ct = cts[i].clone();
        let st = sts[i].clone();
		let now = Instant::now();
	    let (m, ctx, rd, sigma) = g::Client::read(k_r, ct, st, n);
		t_read += now.elapsed();
        reports.push((m, ctx, rd, sigma));
    }

    let rep_size = reports[0].2.0.len() + reports[0].2.1.len() + reports[0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
    for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
		let now = Instant::now();
        let res = g::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
		t_moderate += now.elapsed();
        if !res {
            panic!("Report failed");
        }
    }

    (t_send_offln, t_send_onln, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size)
}

// --------------------
// Trap message scheme
// --------------------
pub fn test_trap(n: usize, ell: usize, msg_size: usize) -> (Duration, Duration, Duration, Duration, Duration, Duration, usize, usize, usize) {
    // Initialize servers
	let moderator = t::Moderator::new();

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
    let mut senders: Vec<t::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = t::Client::new(k_r, pks.clone());
        senders.push(sender);
    }

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut c1c2c3s: Vec<(Vec<u8>, Vec<[u8; 32]>, Vec<u8>)> = Vec::with_capacity(N);
    let mut t_send_offln = Duration::ZERO;
    let mut t_send_onln = Duration::ZERO;
    for i in 0..N {
        let now = Instant::now();
        let (s, rs, c3) = t::Client::send_preprocessing(&pks, n, ell);
        t_send_offln += now.elapsed();

        let now = Instant::now();
        let (c1, c2) = t::Client::send_online(&ms[i], senders[i].k_r, s, rs, n, ell);
        t_send_onln += now.elapsed();

        // Not bundling offline and online
        // let (c1, c2, c3) = g::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2c3s.push((c1, c2, c3));
    }

    let mut cts: Vec<Vec<u8>> = Vec::with_capacity(N);
    for i in 0..N {
        let c1 = c1c2c3s[i].0.clone();
        let ct = onion_encrypt(pks.clone(), c1);
        cts.push(ct);
    }

	// Moderator
    let mut ctxs: Vec<String> = Vec::with_capacity(N);
    let mut sigmas: Vec<Vec<Vec<u8>>> = Vec::with_capacity(N);
    let mut sigma_cs: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut mrts: Vec<Vec<u8>> = Vec::with_capacity(N);
	let mut t_mod_process = Duration::ZERO;
    for i in 0..N {
        let (_, c2, _) = c1c2c3s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

		let now = Instant::now();
        let (sigma, sigma_c) = t::Moderator::mod_process(&moderator.k_m, &c2, &ctx, ell);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());
        sigma_cs.push(sigma_c.clone());

        let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

        mrts.push(mrt);
    }

    let c3_size = c1c2c3s[0].2.len();

    let mut sts: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
	let mut t_process = Duration::ZERO;
	for i in 0..N {
        let (_, _, c3) = c1c2c3s[i].clone();
        let mrt = mrts[i].clone();

        let mut st = (c3, mrt);
		let now = Instant::now();
        st = Server::process(&moderator.sk, st);
		t_process += now.elapsed();
        sts.push(st.clone());
    }

    let mrt_size = sts[0].1.len();

    for i in 0..N {
        let ct = cts[i].clone();
        cts[i] = onion_peel(&moderator.sk, ct);
    }

	// Other servers
    for i in 0..N {
        let mut st = sts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
			let now = Instant::now();
            st = Server::process(&sj.sk, st.clone());
			t_process += now.elapsed();
        }
        sts[i] = st;
    }
    t_process = t_process.div_f32(n as f32);

    for i in 0..N {
        let mut ct = cts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
            ct = onion_peel(&sj.sk, ct.to_vec());
        }
        cts[i] = ct;
    }

	// Receiver
    let mut reports: Vec<Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)>> = Vec::with_capacity(N);
	let mut t_read = Duration::ZERO;
	for i in 0..N {
        let k_r = senders[i].k_r;
        let ct = cts[i].clone();
        let st = sts[i].clone();
		let now = Instant::now();
        let read_out = t::Client::read(k_r, ct, st, n, ell);
		t_read += now.elapsed();
	    // let (m, ctx, rd, sigma) = t::Client::read(k_r, ct, st, n, ell);
        reports.push(read_out);
    }

    let rep_size = reports[0][0].2.0.len() + reports[0][0].2.1.len() + reports[0][0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
	for i in 0..N {
        for j in 0..ell {
            let (m, ctx, rd, sigma) = reports[i][j].clone();
			let now = Instant::now();
            let res = t::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
			t_moderate += now.elapsed();
            if !res {
                panic!("Report failed");
        }
        }
    }

    (t_send_offln, t_send_onln, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size) 
}

// --------------------
// Committed key scheme
// --------------------
pub fn test_comkey(n: usize, msg_size: usize) -> (Duration, Duration, Duration, Duration, Duration, Duration, usize, usize, usize) {
    // Initialize servers
	let moderator = c::Moderator::new();
    let sigma_k = moderator.sigma_k.compress();

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
    let mut senders: Vec<c::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = c::Client::new(k_r, pks.clone(), sigma_k);
        senders.push(sender);
    }

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut c1c2c3s: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let mut t_send_offln = Duration::ZERO;
    let mut t_send_onln = Duration::ZERO;
    for i in 0..N {
        let now = Instant::now();
        let (s, rs, c3) = c::Client::send_preprocessing(&pks, n);
        t_send_offln += now.elapsed();

        let now = Instant::now();
        let (c1, c2) = c::Client::send_online(&ms[i], senders[i].k_r, s, rs);
        t_send_onln += now.elapsed();

        // Not bundling offline and online
        // let (c1, c2, c3) = g::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2c3s.push((c1, c2, c3));
    }

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
	let mut t_mod_process = Duration::ZERO;
	for i in 0..N {
        let (_, c2, _) = c1c2c3s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

		let now = Instant::now();
        let (sigma, sigma_c) = moderator.mod_process(&moderator.k_m, &c2, &ctx);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());
        sigma_cs.push(sigma_c.clone());

        let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

        mrts.push(mrt);
    }

    let c3_size = c1c2c3s[0].2.len();

    let mut sts: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
	let mut t_process = Duration::ZERO;
	for i in 0..N {
        let (_, _, c3) = c1c2c3s[i].clone();
        let mrt = mrts[i].clone();

        let mut st = (c3, mrt);
		let now = Instant::now();
        st = Server::process(&moderator.sk, st);
		t_process += now.elapsed();
        sts.push(st.clone());
    }

    let mrt_size = sts[0].1.len();

    for i in 0..N {
        let ct = cts[i].clone();
        cts[i] = onion_peel(&moderator.sk, ct);
    }

	// Other servers
	for i in 0..N {
        let mut st = sts[i].clone();
        for j in 1..n {
            let sj = &servers[j-1];
			let now = Instant::now();
            st = Server::process(&sj.sk, st.clone());
			t_process += now.elapsed();
        }
        sts[i] = st;
    }
    t_process = t_process.div_f32(n as f32);

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
	let mut t_read = Duration::ZERO;
	for i in 0..N {
        let k_r = senders[i].k_r;
        let ct = cts[i].clone();
        let st = sts[i].clone();
		let now = Instant::now();
	    let (m, ctx, rd, sigma) = senders[i].read(k_r, ct, st, n);
		t_read += now.elapsed();
        reports.push((m, ctx, rd, sigma));
    }

    let rep_size = reports[0].2.0.len() + reports[0].2.1.len() + reports[0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
	for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
		let now = Instant::now();
        let res = c::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
		t_moderate += now.elapsed();
        if !res {
            panic!("Report failed");
        }
    }

    (t_send_offln, t_send_onln, t_mod_process, t_process, t_read, t_moderate, c3_size, mrt_size, rep_size)
}

// --------------------
// Optimized scheme
// --------------------
pub fn test_optimized(n: usize, msg_size: usize) -> (Duration, Duration, Duration, Duration, Duration, usize, usize, usize) {
    // Initialize servers
	let moderator = o::Moderator::new();

	let mut servers: Vec<o::Server> = Vec::with_capacity(n);
	let mut pks: Vec<PublicKey> = Vec::with_capacity(n);

	// Collect server public keys
	pks.push(moderator.get_pk());
	for i in 1..n {
		let si = o::Server::new();
		servers.push(si);
		pks.push(servers[i-1].get_pk());
	}

	// Initialize senders and receivers
    let mut senders: Vec<o::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = o::Client::new(k_r, pks.clone());
        senders.push(sender);
    }

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut ctc2s: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
	let mut t_send = Duration::ZERO;
	for i in 0..N {
		let now = Instant::now();
        let (ct, c2) = o::Client::send(&ms[i], senders[i].k_r, &pks, n);
		t_send += now.elapsed();
        ctc2s.push((ct, c2));
    }

	// Reference sending numbers to compute our overhead
	let mut ref_cts: Vec<Vec<u8>> = Vec::with_capacity(N);
	let mut t_send_ref = Duration::ZERO;
	for i in 0..N {
		let m = ms[i].clone();
		let k_r = senders[i].k_r;

		let now = Instant::now();
		let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&m).expect("");
		let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

		let ct = onion_encrypt(pks.clone(), c1);
		t_send_ref += now.elapsed();
		ref_cts.push(ct);
	}

	// Subtract our baseline to get the true sending overhead of our scheme
	let send_opt = t_send.checked_sub(t_send_ref);
	if let Some(x) = send_opt {
		t_send = x;
	} else {
		t_send = Duration::ZERO;
	}

	// Moderator
    let mut ctxs: Vec<String> = Vec::with_capacity(N);
    let mut sigmas: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut sigma_cs: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut mrts: Vec<Vec<u8>> = Vec::with_capacity(N);
	let mut t_mod_process = Duration::ZERO;
	for i in 0..N {
        let (_, c2) = ctc2s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

		let now = Instant::now();
        let (sigma, sigma_c) = o::Moderator::mod_process(&moderator.k_m, &c2, &ctx);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());
        sigma_cs.push(sigma_c.clone());

        let mrt = bincode::serialize(&(c2.clone(), ctx, sigma, sigma_c)).unwrap();

        mrts.push(mrt);
    }

    let ct_size = ctc2s[0].0.len();

	let mut t_process = Duration::ZERO;
	for i in 0..N {
        let (mut ct, _) = ctc2s[i].clone();
        let mut mrt = mrts[i].clone();

		let now = Instant::now();
        (ct, mrt) = o::Server::process(&moderator.sk, ct, mrt);
		t_process += now.elapsed();
        ctc2s[i].0 = ct;
        mrts[i] = mrt;
    }

	// Reference processing numbers to compute our overhead
	let mut t_process_ref = Duration::ZERO;
	for i in 0..N {
		let mut ct = ref_cts[i].clone();

		let now = Instant::now();
		ct = onion_peel(&moderator.sk, ct);
		t_process_ref += now.elapsed();

		for j in 1..n {
			let ski = &servers[j-1].sk;
			let now = Instant::now();
			ct = onion_peel(&ski, ct);
			t_process_ref += now.elapsed();
		}
	}

	// Divide out # of servers to get time per process operation
	t_process_ref = t_process_ref.div_f32(n as f32);


    let mrt_size = mrts[0].len();

	// Other servers
	for i in 0..N {
        let mut mrt = mrts[i].clone();
        let mut ct = ctc2s[i].0.clone();
        for j in 1..n {
            let sj = &servers[j-1];
			let now = Instant::now();
            (ct, mrt) = o::Server::process(&sj.sk, ct, mrt);
			t_process += now.elapsed();
        }
        ctc2s[i].0 = ct;
        mrts[i] = mrt;
    }
    t_process = t_process.div_f32(n as f32);

	// Subtract our baseline to get the true overhead of our scheme
	let process_opt = t_process.checked_sub(t_process_ref);
	if let Some(x) = process_opt {
		t_process = x;
	} else {
		t_process = Duration::ZERO;
	}

	// Receiver
    let mut reports: Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::with_capacity(N);
	let mut t_read = Duration::ZERO;
	for i in 0..N {
        let k_r = senders[i].k_r;
        let ct = ctc2s[i].0.clone();
        let st = mrts[i].clone();
		let now = Instant::now();
	    let (m, ctx, rd, sigma) = o::Client::read(k_r, ct, st, n);
		t_read += now.elapsed();
        reports.push((m, ctx, rd, sigma));
    }

    let rep_size = reports[0].2.0.len() + reports[0].2.1.len() + reports[0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
	for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
		let now = Instant::now();
        let res = o::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
		t_moderate += now.elapsed();
        if !res {
            panic!("Report failed");
        }
    }

    (t_send, t_mod_process, t_process, t_read, t_moderate, ct_size, mrt_size, rep_size)
}

pub fn test_plain(msg_size: usize) -> (Duration, Duration, Duration, Duration, usize, usize) {

	// Initialize senders and receivers
    let mut senders: Vec<p::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = p::Client::new(k_r);
        senders.push(sender);
    }

	let moderator = p::Moderator::new();

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut c1c2s: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let mut t_send = Duration::ZERO;
    for i in 0..N {

        let now = Instant::now();
        let (c1, c2) = p::Client::send(&ms[i], senders[i].k_r);
        t_send += now.elapsed();

        // Not bundling offline and online
        // let (c1, c2, c3) = p::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2s.push((c1, c2));
    }

	// Moderator
    let mut ctxs: Vec<String> = Vec::with_capacity(N);
    let mut sigmas: Vec<Vec<u8>> = Vec::with_capacity(N);
	let mut t_mod_process = Duration::ZERO;
	for i in 0..N {
        let (_, c2) = c1c2s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

		let now = Instant::now();
        let sigma = p::Moderator::mod_process(&moderator.k_m, &c2, &ctx);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());

    }

	let send_size = ctxs[0].len() + sigmas[0].len() + c1c2s[0].1.len();

	// Receiver
    let mut reports: Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::with_capacity(N);
	let mut t_read = Duration::ZERO;
	for i in 0..N {
        let k_r = senders[i].k_r;
        let (c1, c2) = c1c2s[i].clone();
		let ctx = ctxs[i].clone();
		let sigma = sigmas[i].clone();
		let st = (c2, ctx, sigma);
		let now = Instant::now();
	    let (m, ctx, rd, sigma) = p::Client::read(k_r, c1, st);
		t_read += now.elapsed();
        reports.push((m, ctx, rd, sigma));
    }

    let rep_size = reports[0].2.0.len() + reports[0].2.1.len() + reports[0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
	for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
		let now = Instant::now();
        let res = p::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
		t_moderate += now.elapsed();
        if !res {
            panic!("Report failed");
        } else {
		}
    }

    (t_send, t_mod_process, t_read, t_moderate, send_size, rep_size)
}