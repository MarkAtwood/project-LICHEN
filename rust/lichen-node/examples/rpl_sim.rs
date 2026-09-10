// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Ephemeral, single-owner RPL simulator node (control/IPv6, no messaging).
//!
//! Usage: rpl_sim HOST:PORT SIM_ID NODE_ID SEED_HEX root|leaf DODAG|self
//!                SECONDS X,Y,Z [PEER_PUBKEY_HEX ...]
//!
//! Use a fresh simulation for each run: link tuples, Announce pins/sequences,
//! and DAO state are not restart-safe. The seed is a 32-byte simulator identity.
//! Peers are optional link-verification keys; roots admit DAO origins only from
//! this list, after receiving their signed Announce.
//!
//! NodeServer must use REALTIME and channel 0 (hop_schedule=(0,)). This runner
//! uses Instant because SimRadio does not expose simulator time. Announcements
//! repeat every 5 seconds for short diagnostic runs, rather than 5 minutes.
//! Wrap invocation in `timeout`: SimRadio's blocking TCP has no I/O deadline.

use std::{env, error::Error, net::Ipv6Addr, time::Instant};

use lichen_core::announce::{write_announce_signed_data, AnnounceBuilder};
use lichen_hal::{sim_radio::SimRadio, storage::mem::MemStorage};
use lichen_link::{
    identity::{Identity, PeerIdentity},
    schnorr, PublicKey, Seed,
};
use lichen_node::{
    rpl_stack::{RplReceiveError, RplRuntimeReceiveError, RplRuntimeTrickleError},
    runtime::{RplRuntime, RplRuntimeAction, RplRuntimeConfig},
    AnnounceProcessor, GradientTable, RplReceiveOutcome, RplStack, RxError, SecureStack,
};

const USAGE: &str = "rpl_sim HOST:PORT SIM_ID NODE_ID SEED_HEX root|leaf DODAG|self SECONDS X,Y,Z [PEER_PUBKEY_HEX ...]";

fn key_bytes(text: &str) -> Result<[u8; 32], hex::FromHexError> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

fn signed_announce(identity: &Identity, sequence: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut transcript = [0; 64];
    let len = write_announce_signed_data(
        &identity.iid,
        identity.pubkey.as_bytes(),
        sequence,
        0,
        &[],
        &mut transcript,
    )?;
    let signature = schnorr::sign(&identity.privkey, &identity.pubkey, &transcript[..len]);
    let mut wire = vec![0; 93];
    AnnounceBuilder {
        originator_iid: &identity.iid,
        pubkey: identity.pubkey.as_bytes(),
        seq_num: sequence,
        hop_count: 0,
        rx_channel: 0,
        signature: &signature,
        app_data: &[],
    }
    .write_to(&mut wire)?;
    Ok(wire)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("{USAGE}\nEphemeral control/IPv6 only. Use REALTIME NodeServer, channel 0, and an outer timeout.");
        return Ok(());
    }
    if args.len() < 8 {
        return Err(USAGE.into());
    }
    for name in [&args[1], &args[2]] {
        if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
            return Err("sim/node IDs must be 1..255 bytes without control characters".into());
        }
    }
    let identity = Identity::from_seed(Seed::new(key_bytes(&args[3])?));
    let root = match args[4].as_str() {
        "root" => true,
        "leaf" => false,
        _ => return Err("role must be root or leaf".into()),
    };
    let local = lichen_link::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
    let dodag = if args[5] == "self" && root {
        local
    } else {
        args[5].parse::<Ipv6Addr>()?.octets()
    };
    if dodag[0] != 2 || (root && dodag != local) {
        return Err("DODAG must be the root's upstream Yggdrasil /128".into());
    }
    let seconds: u32 = args[6].parse()?;
    if seconds == 0 {
        return Err("SECONDS must be positive".into());
    }
    let position: Vec<f64> = args[7]
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    if position.len() != 3 || !position.iter().all(|v| v.is_finite()) {
        return Err("position must be three finite coordinates: X,Y,Z".into());
    }
    let peers: Vec<_> = args[8..]
        .iter()
        .map(|key| key_bytes(key).map(|bytes| PeerIdentity::from_pubkey(PublicKey::new(bytes))))
        .collect::<Result<_, _>>()?;
    let radio = SimRadio::connect(
        &args[0],
        &args[1],
        &args[2],
        (position[0], position[1], position[2]),
    )?;
    let mut secure = SecureStack::from_radio(radio, identity.clone(), 128, 0)?;
    for peer in &peers {
        secure.add_peer(peer.clone());
    }
    // ponytail: supported in-memory storage, deliberately no restart claim.
    let announces = AnnounceProcessor::new(GradientTable::new(64));
    let mut owner = if root {
        RplStack::provision_root(secure, local, dodag, announces, MemStorage::new())?
    } else {
        RplStack::provision_leaf(secure, local, dodag, announces, MemStorage::new())?
    };
    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    // Node-specific timer offsets keep simultaneous starts from staying in lockstep.
    let offset = u32::from_be_bytes(identity.iid[..4].try_into()?);
    owner.trickle_start(0, offset);
    let mut runtime = RplRuntime::new(RplRuntimeConfig::default(), 0);
    let mut announce_at = 500 + u64::from(identity.iid[7]) * 4;
    let mut sequence = 0u16;
    println!(
        "READY node={} role={} ipv6={} pubkey={} ephemeral=true",
        args[2],
        args[4],
        Ipv6Addr::from(local),
        hex::encode(identity.pubkey.as_bytes())
    );

    while now() < u64::from(seconds) * 1_000 {
        if now() >= announce_at {
            sequence = sequence.wrapping_add(1);
            let wire = signed_announce(&identity, sequence)?;
            let sent = owner.send_announce(&wire, now() as u32).await;
            println!("{} TX Announce seq={sequence} result={sent:?}", now());
            announce_at = now() + 5_000;
        }
        let poll = owner
            .runtime_poll(&mut runtime, now())
            .map_err(|e| format!("poll: {e:?}"))?;
        match poll.action {
            RplRuntimeAction::Receive { .. } => {
                match owner.runtime_receive(&mut runtime, poll.action, now).await {
                    Ok(received) => {
                        if let Some(outcome) = received.received {
                            match &outcome {
                                RplReceiveOutcome::DeliveredIpv6(packet) => {
                                    println!("{} RX IPv6 len={}", now(), packet.ipv6.len());
                                }
                                _ => println!("{} RX {outcome:?}", now()),
                            }
                            if let RplReceiveOutcome::AnnouncementAccepted { peer, .. } = outcome {
                                if root && peers.iter().any(|allowed| allowed.pubkey == peer.pubkey)
                                {
                                    owner.admit_dao_origin(peer.iid)?;
                                    println!(
                                        "{} DAO origin admitted iid={}",
                                        now(),
                                        hex::encode(peer.iid)
                                    );
                                }
                            }
                        }
                    }
                    Err(error @ RplRuntimeReceiveError::Action(_))
                    | Err(
                        error @ RplRuntimeReceiveError::Receive(RplReceiveError::Receive(
                            RxError::RadioRx,
                        )),
                    ) => return Err(error.into()),
                    Err(error) => eprintln!("{} RX rejected: {error}", now()),
                }
            }
            RplRuntimeAction::DaoTransmit => {
                let sent = owner.send_dao().await;
                let completed = if sent.is_ok() {
                    owner.runtime_complete_dao_transmit(&mut runtime, now())
                } else {
                    owner.runtime_fail_dao_transmit(&mut runtime, now())
                };
                completed.map_err(|e| format!("DAO completion: {e:?}"))?;
                println!("{} TX DAO result={sent:?}", now());
            }
            RplRuntimeAction::TrickleTransmit => {
                match owner
                    .runtime_complete_trickle_transmit(&mut runtime, poll.action, now())
                    .await
                {
                    Err(error @ RplRuntimeTrickleError::Action(_)) => return Err(error.into()),
                    result => println!("{} TX DIO result={result:?}", now()),
                }
            }
            RplRuntimeAction::TrickleExpire => {
                owner.runtime_complete_trickle_expire(&mut runtime, poll.action, now(), offset)?;
            }
        }
    }
    println!(
        "DONE node={} joined={} parent={:?}",
        args[2],
        owner.rpl_node().is_joined(),
        owner.rpl_node().preferred_parent().map(Ipv6Addr::from)
    );
    Ok(())
}
