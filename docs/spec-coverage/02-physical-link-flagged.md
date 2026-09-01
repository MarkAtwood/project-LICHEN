# spec/02-physical-link.md — flagged set (sweep 2026-09-01)

Flag criteria: (a) low confidence, (b) ambiguous or divergent classification,
(c) §06-security / oscore-EDHOC semantics (n/a for this section). Not yet
covered here: the 10 not-implemented MUST gaps already filed as beads.

## Divergent

### R-02-001 — §3.1 "LoRa CSS as implemented by Semtech SX126x and SX127x"
- Classification: divergent (SX126x implemented; SX127x driver absent)
- Evidence: SX126x — rust/lichen-embassy/src/esp32s3.rs:11-69 (lora-phy 3), lichen/drivers/lora/lr1110/. SX127x — only modeled: rust/lichen-core/src/airtime.rs:32,203, python/src/lichen/board_intake.py:48-52. No SX127x driver in rust/ or lichen/drivers/.
- Question for Opus: Is SX127x driver support in scope for the current phase (target hardware includes SX1276/78 boards like T-Beam/Heltec V2), or is the airtime-model-only state acceptable to record as planned? Should the spec sentence be softened to "SX126x (SX127x planned)"?

### R-02-006 — §3.2 Sync Word 0x34 (distinct from Meshtastic 0x2B)
- Classification: divergent — constant defined, never programmed onto any radio
- Evidence: rust/lichen-core/src/constants.rs:4 `LORA_SYNC_WORD=0x34` has zero callers; C lichen/subsys/lichen/l2/lora_l2.c:299-303 sets no sync word and leaves Zephyr `public_network=false` (Semtech private sync, not 0x34); python phy_params.py:30 is config-only. All 0x34 assertions live in the LCI `/config/radio` CBOR store (lichen-client/radio_config.rs, lichen/tests/coap_config/main.c, lci_radio_config.json).
- Question for Opus: This is an interop-critical gap — if the C radio actually listens on the Semtech private sync byte while the spec says 0x34, do Rust/C nodes even hear each other on hardware? Does the Zephyr lr1110 driver expose a sync-word API (or does `public_network` need a custom value), and should the fix go in lora_l2.c or the driver? Confirm no other layer already programs 0x34.

### R-02-010 — §3.3 N_CHANNELS from active regional config, not a global constant
- Classification: divergent (partial)
- Evidence: python channel_plan.py:73-75 derives from plan; C CONFIG_LICHEN_N_CHANNELS is a build-time Kconfig constant (link/Kconfig:287-294); rust/python announce rx_channel hardcapped <8 (lichen-node/src/scheduler.rs:194; announce/scheduler.py:58,120); no runtime plan→n_channels wiring in R/C.
- Question for Opus: Is the 8-channel cap acceptable for the regional plans currently shipped (EU868 has 8 data-bearing channels after CH0?) or should the cap be lifted to plan-derived N? Note US915 has 64 uplink channels — the cap would break it.

### R-02-011 — §3.3 hash-based channel selection `data_ch = 1 + (hash(src_iid ^ dst_iid) mod (N-1))`
- Classification: divergent — spec formula implemented nowhere; all impls follow 02a §2a.3.1 (FNV-1a32 over eui64‖epoch)
- Evidence: spec/02-physical-link.md:42 is the only occurrence of XOR-of-IIDs; P ccp.py:68-115, R lichen-core/src/rf_health.rs:385-395, C link_ctx.c:722,754 + sync_hop.c implement `FNV1A32(eui64_be‖epoch_le)` with density>10→CH0; vectors ccp15.json + ccp_select_channel_endianness.json pin the implemented form.
- Question for Opus: Confirm the spec §3.3 formula is stale and should be rewritten to match 02a §2a.3.1 + vectors (the decision file contains no entry covering this). This is a spec-edit, not a code change.

### R-02-014 — §3.3 Regional params: EU868 8ch, US915 64 uplink + 8 downlink
- Classification: divergent (partial)
- Evidence: P channel_plan.py:110-138 implements EU868 exact frequencies + US915 64 uplink; US915 8 downlink modeled nowhere (rg "downlink": only LR-FHSS/Meshtastic hits); R lichen-hal/src/lib.rs:232-265 and C lora_l2_tx.c:322,331 have base-freq + spacing only, no channel lists.
- Question for Opus: For a LoRa mesh (not LoRaWAN), is a separate downlink channel band meaningful, or should the spec drop "64 uplink + 8 downlink" in favor of a single channel list? Needs a design call before any code gap is filed.

### R-02-016 — §3.4 "Nodes MUST use assigned SF for all TX after joining"
- Classification: divergent — codec + C parse wired, but nothing ever emits ASSIGNED_SF
- Evidence: R lichen-core/src/constants.rs:66 + sf_assignment.rs:149-247 (make/parse/tracker, tracker dead code); C rpl_messages.h:70, rpl_sf_assignment.c:22-40, dodag.c:667-674 parse→lora_l2_assign_sf→TX datarate (lora_l2.c:231-244,308); P link/sf_assignment.py. `make_assigned_sf_option` has no production caller in any impl; no gateway emits it.
- Question for Opus: Where should emission live — border-router DIO construction (which crate/file), and should the join-response path also carry it (spec mentions both)? Is the intended C gateway emitter lichen/apps/gateway?

### R-02-029 — §3.5 Downgrade thresholds (MUST increase SF at density>10 etc.)
- Classification: divergent — C and secondary Python selector still use density>8
- Evidence: R rf_health.rs:16 DENSITY_HIGH=10 ✓ and P ccp.py:352 `density > 10` ✓; C lichen/subsys/lichen/routing/gradient.c:320 `density > 8` ✗ (comment cites stale 2a.8); P link/adaptive_sf.py:138 `density > 8` ✗ plus a non-spec table shortcut :129-133. Bead project-LICHEN-worker6-b7z9.58 was closed with the fix marked complete, but these two sites retain >8.
- Question for Opus: Confirm the residual sites are exactly these two (agent also cited C link_ctx.c:705 and lora_l2_tx.c:587 in b7z9.58 — link_ctx.c now reads >10; verify lora_l2_tx.c:587) and whether committed vectors still pin 8 anywhere (ccp16.json select_channel_timing, ccp13.json).

### R-02-036/037/040/041 — §3.7 LR-FHSS advertisement/negotiation flags
- Classification: divergent — implemented+tested in Python only; Rust has a CoAP capability bitmap only; C absent
- Evidence: P link/lr_fhss.py:27-28,70-109 + tests/link/test_lr_fhss_vectors.py (lr_fhss_capability.json); R lichen-gateway/src/resources.rs:59,190 (capability bitmap, not DIO flag); C zero hits.
- Question for Opus: Should the DIO/Announce flag layer be ported to Rust/C before the PHY driver exists (cheap wire-compat work), or deliberately deferred with the driver (spec §3.7 says driver is a child issue)?

### R-02-046 — §4.1 "Verifiers MUST reject the legacy unprefixed transcript… MUST NOT accept both"
- Classification: divergent — tested in Rust + Python; C has no explicit rejection test
- Evidence: R schnorr.rs:655-699 test link_domain_rejects_legacy_and_other_profile_signatures; P test_protocol_vector_security.py:228-229; C schnorr48.c has a single verification path (structurally cannot accept a second transcript) but no test pins legacy-rejection.
- Question for Opus: Is a C test asserting legacy/unprefixed transcript rejection required for the interop bar, or is single-path construction sufficient evidence?

### R-02-057 — §4.2 "On overflow implementations MUST evict the least-recently-verified binding"
- Classification: divergent — Rust evicts LRU correctly; Python evicts unless eviction-blocked (then fails closed); C persist-mode never evicts (refuses admission -ENOSPC)
- Evidence: R link_layer.rs:556,940-968,2220-2257; P link_layer.py:1644-1659 + gradient.py:27 MAX_ENTRIES=64; C l2/lichen_l2_peer.c:341-347 under CONFIG_LICHEN_LINK_REPLAY_PERSIST (documented trust-lineage protection).
- Question for Opus: Is C persist-mode refusal (and Python fail-closed-under-blocker) an accepted deviation from the MUST-evict wording, or should the spec gain an "implementations MAY fail closed when eviction would break lineage integrity" carve-out? Related open bead: project-LICHEN-worker6-2dd7 (announce trust store brick).

### R-02-064 — §4.4 "MUST initialize epoch to a random value uniformly distributed in [128,255]"
- Classification: divergent — Python EpochStore.boot_epoch cold-boot fallback is fixed 128
- Evidence: P link_layer.py:196 uses secrets (conformant); C link_ctx.c:237 uses rand_byte&0x7F (conformant); P link/epoch_store.py:48-57 boot_epoch() returns fixed 128 when no stored epoch, and test_epoch_store.py:11 pins that behavior.
- Question for Opus: EpochStore is the persistence-helper path (LinkLayer default is random). Is fixed-128 acceptable because persistence is RECOMMENDED and a persisted-epoch write follows immediately, or must boot_epoch randomize too?

### R-02-072 — §4.4 "Persisted replay records MUST bind full pubkey, opaque key-generation id, highest counter, window bitmap, monotonic record generation under integrity"
- Classification: divergent (C)
- Evidence: R binds all elements under Schnorr-48 (link_layer.rs:725-782,1237-1247); P binds digest chain + per-peer counter/bitmap, generation via retired/rekeyed sets (no explicit opaque id); C replay_persist.c has keyed-BLAKE2b integrity + pubkey + tx_epoch + per-peer floor, but NO generation id and NO window bitmap (floor `seq+31`, restore marks whole window seen — conservative/fail-closed).
- Question for Opus: Does the C floor+full-window-seen restore satisfy the intent (fail-closed, no state resurrection) well enough to amend the spec wording, or must C serialize the bitmap and generation id (record-size cost on STM32WL)?

### R-02-079/080 — §4.5 dad_retry loop; "MUST match test/vectors/short_addr_dad.json"
- Classification: divergent (C) — derivation primitives bit-exact, but no dad_retry loop and no C consumer of short_addr_dad.json / dad_hash_clarification.json
- Evidence: R lichen-rpl/src/address_assignment.rs:1074-1090 + short_addr_vectors.rs; P short_addr.py:154-171 + test_vectors.py:4044-4129; C l2/ipv6_addr.c:45-85 (primitives only, bit-exact per bead l1qw.4.8.3 history); no C consumer of either JSON.
- Question for Opus: Where does C short-address DAD retry belong — RPL address_assignment equivalent in lichen/subsys/lichen/rpl/, and should the C test harness gain a JSON consumer like lichen/tests/rpl_sf_assignment does?

## Ambiguous / low confidence

### R-02-009 — §3.3 "All nodes MUST listen when idle" (CH0)
- Classification: ambiguous
- Evidence: listening on CH0 is implicit via default rx_channel=0 (C lora_l2.c:183,614; R stack.rs:254); C Kconfig link/Kconfig:283-285 states intent; no explicit idle-listen enforcement or channel-hop state machine found.
- Question for Opus: Does any implementation actually guarantee idle listen on CH0 while also serving data channels, or is single-channel blocking RX the de-facto behavior (making the MUST unimplementable without the multi-channel RX work in R-02-015/019)?

### R-02-012 — §3.3 Rendezvous "sender uses announced channel (TOFU pinning)"
- Classification: ambiguous (selection layer tested; TX-path wiring gap)
- Evidence: Announce carries rx_channel (C routing/announce.c:123,267; R announce.rs:53,74-83; P announce/scheduler.py); selection honors announced channel for pinned peers (P link/channel.py:112-119; R lib.rs:172-187); P pins peer rx_channel with expiry (node.py:1415-1419) — but P Node.send() (node.py:1461) never reads `_peer_rx_channel` for unicast TX.
- Question for Opus: Is the pinned rx_channel intended to drive unicast TX channel selection (making Node.send() a bug), or is it only for rendezvous scheduling? ccp9_rendezvous.json validates selection only.

### R-02-015 — §3.3 "Gateway RX on all channels"
- Classification: ambiguous
- Evidence: R lichen-hal/src/lib.rs:161-165 concentrator multi-channel API + gateway config rak2287/SX1302 (config.rs:142) exist; C gateway RX is single-channel blocking lora_recv (apps/gateway/src/main.c:689-730); no scanning loop anywhere.
- Question for Opus: Is SX1302 concentrator multi-channel RX actually functional end-to-end in the Rust gateway (channel configuration + demod), or is the HAL API unexercised?

### R-02-031 — §3.5 "Measurement MUST use TX-time based occupancy (total detected airtime / observation window)"
- Classification: ambiguous
- Evidence: R rf_health.rs:141-212 BusyPercentSampler ("TX-time based… Never RSSI-derived (spec MUST)", test :1311) and P ccp.py:118-136 — but both count OWN-node TX airtime only, not "total detected airtime" of the channel.
- Question for Opus: Does "total detected airtime" require sensing other nodes' transmissions (CAD/detect), or is own-node airtime occupancy the intended metric (in which case spec wording should be tightened)? Affects duty-cycle and load_factor semantics.

### R-02-068 — §4.4 "Replay key is (SignerPublicKey, KeyGeneration)… aliases MUST NOT replace either component"
- Classification: ambiguous
- Evidence: R and P key replay state by PublicKey alone (link_layer.rs:399-400; link_layer.py:1664) with generation handled via retirement semantics (Arc tokens, retired_remote_keys); C keys by pubkey memcmp, no generation concept; the literal composite key exists only in replay_window.json security-domain vectors (Python-consumed only).
- Question for Opus: Is reset-on-retirement an accepted equivalent of the composite key (a same-pubkey generation change is then unrepresentable by construction), or should a generation-tagged map key be required? Rust has durable_key_generation available to key on.

### R-02-035 — §3.6 SFN coordinated-transmission deltas (flagged despite not-implemented: scope question)
- Classification: not-implemented (feature absent); time-sync substrate implemented+tested
- Evidence: no SFN delta/combining code (rg); substrate: P timing/sfn.py, DIO Time Option (R lichen-link/src/dio_time.rs, C rpl_messages.h:68), PPS/GNSS strata, desync FSM + ccp16-desync.json.
- Question for Opus: Is §3.6 planned for the current phase at all (no epic/bead found), or should it be marked future-work in the spec with an explicit pointer, so the sweep can stop treating it as a live gap?

### R-02-013 — §3.3 Gateway-assigned channel (DIO carries channel, MRHOF variant)
- Classification: not-implemented (non-MUST coordination primitive; no bead filed)
- Evidence: no DIO channel option exists in any impl; ccp9-rendezvous.json `scheduled_rendezvous` case is vector-semantics only.
- Question for Opus: Should this primitive be dropped from §3.3 (superseded by CCP-9 mechanisms in 02a) or tracked as a future MRHOF extension? Spec-text decision only.

## Vector-consumer cross-implementation gaps (pattern, not single req)

Multiple MUST-match-vector requirements have consumers in only one or two implementations:
- ccp9.json, ccp9-rendezvous.json, ccp9_rendezvous.json, ccp4_regional_channel_plans.json, channel_plan_selection.json: Python-only consumers.
- replay_window.json (security_domain_vectors skipped by Rust), epoch_rollover.json: no C consumer.
- ccp16_load_balance.json: no Rust/C consumer. ccp16_utilization.json: no C consumer. ccp16-desync.json: no Rust consumer.
- relay_signer_chain.json: Rust/C unconsumed (semantics covered via different oracles).
- mic_length_selector.json, frame_length_boundaries.json: no Rust consumer (C hand-parity).
- sf_assignment.json: no Python consumer (bead project-LICHEN-worker6-6g4z).
- Question for Opus: Should a standing policy bead require every new vector file to land with consumers in ≥2 implementations before merge? Existing beads (6g4z) track some individually.