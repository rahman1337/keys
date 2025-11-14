// src/main.rs
use bitcoin::util::key::PrivateKey;
use bitcoin::{Address, Network};
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::Hash;
use crossbeam_channel::{unbounded, Sender};
use core_affinity;
use num_cpus;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Target collections of 20-byte payloads (raw bytes).
#[derive(Default)]
struct Targets {
    // P2PKH: hash160(pubkey)
    p2pkh: HashSet<[u8; 20]>,
    // P2SH: hash160(redeem_script)
    p2sh: HashSet<[u8; 20]>,
    // P2WPKH: witness program (should be 20 bytes for v0 P2WPKH)
    p2wpkh: HashSet<[u8; 20]>,
}

fn load_targets<P: AsRef<Path>>(path: P) -> std::io::Result<Targets> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut targets = Targets::default();

    for line in reader.lines() {
        let line = line?;
        let s = line.trim();
        if s.is_empty() {
            continue;
        }

        // Try to parse bitcoin address using rust-bitcoin
        match Address::from_str(s) {
            Ok(addr) => match addr.payload() {
                bitcoin::util::address::Payload::PubkeyHash(h) => {
                    targets.p2pkh.insert(h.into_inner());
                }
                bitcoin::util::address::Payload::ScriptHash(h) => {
                    targets.p2sh.insert(h.into_inner());
                }
                bitcoin::util::address::Payload::WitnessProgram(wp) => {
                    // Only take witness v0 program of length 20 (P2WPKH)
                    if wp.version().to_u8() == 0 && wp.program().len() == 20 {
                        let mut b = [0u8; 20];
                        b.copy_from_slice(wp.program());
                        targets.p2wpkh.insert(b);
                    } else {
                        // other witness versions / lengths ignored for now
                    }
                }
                _ => {
                    // ignore unknown payloads
                }
            },
            Err(_) => {
                // Could not parse address; ignore or log.
                // We intentionally avoid printing here to keep the load fast.
            }
        }
    }

    Ok(targets)
}

/// Build P2SH-P2WPKH redeem script from a 20-byte pubkey-hash:
/// redeem_script = OP_0 PUSH_DATA(20) <20-byte-hash>
fn redeem_script_for_wpkh(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    // OP_0 (0x00) followed by push 20 (0x14) then the 20 bytes
    let mut v = Vec::with_capacity(22);
    v.push(0x00); // OP_0
    v.push(0x14); // push 20 bytes
    v.extend_from_slice(pubkey_hash);
    v
}

fn main() -> std::io::Result<()> {
    // --- CONFIG ---
    let addresses_file = "btc.txt";
    let found_file = "found.txt";
    // ----------------

    let targets = Arc::new(load_targets(addresses_file)?);
    let total_targets = {
        targets.p2pkh.len() + targets.p2sh.len() + targets.p2wpkh.len()
    };
    eprintln!(
        "Loaded {} target entries (p2pkh={}, p2sh={}, p2wpkh={}) from `{}`",
        total_targets,
        targets.p2pkh.len(),
        targets.p2sh.len(),
        targets.p2wpkh.len(),
        addresses_file
    );

    // Writer thread: single consumer for matched results
    let (tx, rx) = unbounded::<String>();
    let found_path = found_file.to_string();
    let writer_handle = {
        let rx = rx.clone();
        thread::spawn(move || {
            let mut fh = OpenOptions::new()
                .create(true)
                .append(true)
                .open(found_path)
                .expect("unable to open found file for writing");
            // flush every N writes or every few seconds. We'll flush after each write to ensure durability.
            for msg in rx.iter() {
                if let Err(e) = fh.write_all(msg.as_bytes()) {
                    eprintln!("Failed to write found entry: {}", e);
                }
                if let Err(e) = fh.flush() {
                    eprintln!("Failed to flush found file: {}", e);
                }
            }
        })
    };

    // Counters
    let generated = Arc::new(AtomicU64::new(0));
    let matches = Arc::new(AtomicU64::new(0));

    // status thread
    {
        let g = Arc::clone(&generated);
        let m = Arc::clone(&matches);
        thread::spawn(move || {
            let start = Instant::now();
            loop {
                thread::sleep(Duration::from_secs(2));
                let gen = g.load(Ordering::Relaxed);
                let mat = m.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64().max(1.0);
                let rate = gen as f64 / elapsed;
                eprintln!(
                    "Generated: {:>12}  Matches: {:>6}  Rate: {:>8.0} keys/sec",
                    gen, mat, rate
                );
            }
        });
    }

    // Determine worker threads
    let num_threads = num_cpus::get();
    eprintln!("Spawning {} worker threads (logical cores)", num_threads);

    // Create worker threads
    let mut handles = Vec::with_capacity(num_threads);
    for thread_idx in 0..num_threads {
        let tx = tx.clone();
        let targets = Arc::clone(&targets);
        let generated = Arc::clone(&generated);
        let matches = Arc::clone(&matches);

        let handle = thread::spawn(move || {
            // Optional: pin this thread to a core to reduce migration
            if let Some(core_ids) = core_affinity::get_core_ids() {
                let id = core_ids[thread_idx % core_ids.len()];
                let _ = core_affinity::set_for_current(id);
            }

            // per-thread secp context
            let secp = Secp256k1::new();

            // fast RNG seeded from OsRng once
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("getrandom failed");
            let mut rng = ChaCha20Rng::from_seed(seed);

            // per-thread temporary buffers
            // Loop forever (user should ctrl+c to stop)
            loop {
                // draw 32 bytes of entropy
                let mut sk_bytes = [0u8; 32];
                rng.fill_bytes(&mut sk_bytes);

                // map to SecretKey (skip invalid)
                let secret = match SecretKey::from_slice(&sk_bytes) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                // public key (compressed)
                let secp_pub = SecpPublicKey::from_secret_key(&secp, &secret);
                let pubkey_bytes = secp_pub.serialize(); // 33 bytes compressed

                // compute HASH160(pubkey) -> 20 bytes
                let pubkey_hash = Hash160::hash(&pubkey_bytes);
                let pubkey_hash_bytes: [u8; 20] = pubkey_hash.into_inner();

                // Check P2PKH match
                if targets.p2pkh.contains(&pubkey_hash_bytes) {
                    matches.fetch_add(1, Ordering::Relaxed);
                    // produce WIF and address string for user output
                    let pk = PrivateKey {
                        compressed: true,
                        network: Network::Bitcoin,
                        key: secret,
                    };
                    let wif = pk.to_wif();
                    // address string form for clarity: build p2pkh address from pubkey
                    let addr = Address::p2pkh(
                        &bitcoin::PublicKey {
                            compressed: true,
                            key: secp_pub,
                        },
                        Network::Bitcoin,
                    );
                    let out = format!("{}\n{}\n", wif, addr.to_string());
                    let _ = tx.send(out);
                }

                // Check P2WPKH match (witness program equals pubkey_hash for v0 P2WPKH)
                if targets.p2wpkh.contains(&pubkey_hash_bytes) {
                    matches.fetch_add(1, Ordering::Relaxed);
                    let pk = PrivateKey {
                        compressed: true,
                        network: Network::Bitcoin,
                        key: secret,
                    };
                    let wif = pk.to_wif();
                    let addr = Address::p2wpkh(
                        &bitcoin::PublicKey {
                            compressed: true,
                            key: secp_pub,
                        },
                        Network::Bitcoin,
                    )
                    .expect("p2wpkh address creation failed");
                    let out = format!("{}\n{}\n", wif, addr.to_string());
                    let _ = tx.send(out);
                }

                // Check P2SH-P2WPKH: compute redeem script, then hash160(redeem_script) compare to p2sh set
                let redeem = redeem_script_for_wpkh(&pubkey_hash_bytes);
                let redeem_hash = Hash160::hash(&redeem);
                let redeem_hash_bytes: [u8; 20] = redeem_hash.into_inner();
                if targets.p2sh.contains(&redeem_hash_bytes) {
                    matches.fetch_add(1, Ordering::Relaxed);
                    let pk = PrivateKey {
                        compressed: true,
                        network: Network::Bitcoin,
                        key: secret,
                    };
                    let wif = pk.to_wif();
                    // p2sh-p2wpkh address creation using bitcoin crate helpers:
                    let addr = Address::p2shwpkh(
                        &bitcoin::PublicKey {
                            compressed: true,
                            key: secp_pub,
                        },
                        Network::Bitcoin,
                    )
                    .expect("p2shwpkh address creation failed");
                    let out = format!("{}\n{}\n", wif, addr.to_string());
                    let _ = tx.send(out);
                }

                generated.fetch_add(1, Ordering::Relaxed);
            }
        });

        handles.push(handle);
    }

    // Wait for all worker threads (they run forever until killed)
    for h in handles {
        let _ = h.join();
    }

    // ensure writer thread clean shutdown (unreachable in normal run)
    drop(tx);
    let _ = writer_handle.join();

    Ok(())
}
