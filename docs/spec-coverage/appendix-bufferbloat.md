## spec/appendix-bufferbloat.md — coverage (sweep 2026-08-31)

16 requirements extracted (0 capitalized RFC 2119 keyword rows — the appendix
is written in design-principle prose with three lowercase "must"s at lines 27,
90, 175; the lowercase-must normativity question is the section-level flag).
IDs use prefix `R-ABF` (appendix bufferbloat), following the `R-ABR` precedent.
The "Problem", "LoRa-Specific Factors", "Why Not CoDel/CAKE?", and "Further
Reading" sections are informative rationale with no behavioral requirements —
not extracted. This appendix is unusually well instrumented: dedicated vector
set tx_queue_{bounded,expiry,priority,implementation}.json,
forwarding_buffer.json (13 vectors), no_silent_drops.json,
bufferbloat_congestion.json, consumed by all three stacks. Gap beads filed
under epic `project-LICHEN-worker6-b7z9`, labels `bufferbloat` + `spec-gap`:
**0** (no capitalized MUSTs; keyword-less divergences noted in matrix per
preamble, not beaded). Gap-bead overflow: 0 (0 MUST-gaps; cap 10). If Opus
rules the lowercase musts normative, pre-authorized bead text for the
R-ABF-003/011/016 gaps lives in
`docs/spec-coverage-appendix-bufferbloat-flagged.md`.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-ABF-001 | Every queue has an explicit small bound; full → reject with error (backpressure), never silently queue (Design Principles 1) | implemented+tested | Rs: TxQueueError::QueueFull tx_queue.rs:216-225 (push :501-542; test queue_full_error :1112) + ForwardError::QueueFull forward_buffer.rs:28-34. Py: QueueFullError timing/tx_queue.py:54,185 + link/tx_queue.py:73, raised through live send link_layer.py:1428. C: -ENOBUFS tx_queue.h:169-170 + test_queue_full_returns_enobufs tests/tx_queue/main.c:281. BLE GATT QueueFull gatt.rs:92. Vectors tx_queue_bounded.json backpressure_* consumed Rs bufferbloat_vectors.rs + Py tests | high |
| R-ABF-002 | TX queue: 4 packets max | implemented+tested | Rs TX_QUEUE_CAPACITY=4 tx_queue.rs:240 (test capacity_is_four :1334) + vector capacity_default_4; Py link TX_QUEUE_CAPACITY=4 link/tx_queue.py:31 (timing CAPACITY=4); C TX_QUEUE_SIZE=LICHEN_FRAME_POOL_CAPACITY=4 frame_pool.h:21, tx_queue.h:49 + test_shared_vector_constants main.c:148 | high |
| R-ABF-003 | Forwarding: 2 packets per source max; total forwarding buffer 16 packets max (Design Principles 1 + Forwarding Buffer) | divergent | Mechanism implemented+tested at unit level in all stacks: Rs MAX_FORWARDING_SOURCES=8/MAX_PACKETS_PER_SOURCE=2 forward_buffer.rs:20-23 + tests per_source_limit_enforced/max_sources_eviction :319-384; Py ForwardingBuffer router.py:144-239 (embedded Router field :401) + link/forwarding_buffer.py:91 + test_forwarding_buffer.py (13 forwarding_buffer.json vectors) + test_router.py:958; C Kconfig 8/2/16 routing/Kconfig:121-144, router.h:65-75 + tests/routing_fwd_buffer (nacks_sent==1 main.c:123). NOT wired into any relay datapath: Rs Stack.queue_forward stack.rs:704 zero callers; Py try_buffer/dequeue zero callers in src (node forward path node.py:1451 never enqueues); C lichen_router_fwd_enqueue + lichen_router_init zero callers (router compiled in via CONFIG_LICHEN_ROUTING=y prj.conf:31 but never instantiated) | high — flagged; library-only in all 3 stacks |
| R-ABF-004 | BLE GATT: 8 messages max (returns QueueFull) (Design Principles 1) | implemented+tested | Rs lichen-meshtastic gatt.rs:39 MAX_QUEUE_DEPTH=8, GattError::QueueFull :92, queue_from_radio :371-379 (Deque push fail→QueueFull); in-file tests: full queue asserts Err(QueueFull) :580-587, deadline expiry :761+ | high |
| R-ABF-005 | Packets have deadlines; queued packets past deadline are dropped (Design Principles 2) | implemented+tested | Rs expire_before tx_queue.rs:547-573 wired into push/pop/peek/count; Py expire_stale timing/tx_queue.py:192 + link/tx_queue.py + link_layer drain :1442; C expiry in push/pop (test_invalid_incoming_deadline_expires_stale_first main.c:214). Vectors tx_queue_expiry.json (boundary now≥deadline, pop/peek/reserve trigger, requeue preserves deadline) consumed Rs bufferbloat_vectors.rs:47, Py timing/test_tx_queue_vectors.py + test_tx_queue_gen_loader.py, C tx_queue gen_vectors.py | high |
| R-ABF-006 | Routing control (RPL DIO/DAO): 5 s deadline (Design Principles 2) | implemented+tested | DEADLINE_ROUTING_MS=5000: Rs tx_queue.rs:246, Py link/tx_queue.py:35 + timing :27, C TX_DEADLINE_ROUTING_MS tx_queue.h:72-76; vector tx_queue_expiry.json default_deadline_routing asserted Rs bufferbloat_vectors.rs:51 | high |
| R-ABF-007 | ACK/NACK: 10 s deadline (Design Principles 2) | divergent | 10 s constant exists + vector-pinned: Rs DEADLINE_ACK_MS=10_000 tx_queue.rs:253, C TX_DEADLINE_ACK_MS tx_queue.h:73, Py timing :28; vector default_deadline_ack. BUT ACK is an alias of ROUTING priority in all stacks (C tx_queue.h:63; Py tx_queue_expiry.json note; Rs doc :250-252) and the effective default for ACK-priority packets is ROUTING's 5 s; no found send path passes 10 s explicitly (Rs push_tx_queue maps Routing→5 s lichend.rs:547-553; Py link_layer ACK SCHC-frag controls :1364 use default; Py link/tx_queue.py:36 defines DEADLINE_ACK_MS=5000) | low — flagged; alias-default vs spec 10 s |
| R-ABF-008 | Application data: configurable, default 60 s (Design Principles 2) | implemented+tested | DEADLINE_NORMAL_MS=60000 all stacks (Rs :259, Py link :38/timing :30, C tx_queue.h:75) + vector default_deadline_normal; every push API accepts an absolute-deadline override (configurable). Caveat: default caller priority at C L2 / Py link boundaries is BULK (lora_l2_tx.c:406, link_layer.py:1285) whose default is 120 s; 60 s binds to P3 Normal | high |
| R-ABF-009 | Priority table: 0 routing control, 1 link ACKs, 2 urgent app, 3 bulk; higher priority preempts lower (Design Principles 3) | divergent | Preemption implemented+tested everywhere (Rs try_preempt tx_queue.rs:578-633 + tests :1255-1331; Py push preemption timing/tx_queue.py:181; C test_priority_preemption main.c:306) + vectors. But the appendix's 4-level table diverges from the implemented 5-level P0=SOS/P1=ROUTING+ACK/P2=URGENT/P3=NORMAL/P4=BULK model (Rs tx_queue.rs:273-284, Py link/tx_queue.py:42-70, C tx_queue.h:60-68), which matches main spec 07-transport §10.2.4 (row R-07-033) and tx_queue_priority.json | high — flagged; appendix vs main-spec table coherence |
| R-ABF-010 | Queue full → sender gets error: ENOBUFS/QueueFull for immediate sends; senders must handle (Design Principles 4) | implemented+tested | Same surfaces as R-ABF-001: C lora_l2_tx propagates push failure lora_l2_tx.c:406-413; Py send raises QueueFullError to caller (link_layer.py:1428 + tests/link/test_link_tx.py); Rs TxQueue::push returns Err (tests :1112-1133). Caveat: Rs daemon push helpers swallow to warn+drop (lichend.rs:555-558,586-589) — flagged (see flagged set) | high |
| R-ABF-011 | NACK to mesh source for mesh-forwarded packets when full (Design Principles 4+5; "send NACK upstream") | not-implemented | No NACK message/transmission in any stack (rg -i nack: comments, counters, hooks only). C: nacks_sent counter + -ENOBUFS, no frame router.c:1410-1411 (test asserts counter routing_fwd_buffer main.c:123). Py: on_drop hook "caller uses this to send NACK" forwarding_buffer.py:56,121 zero callers; vector-designated NACK shape = ICMPv6 DEST_UNREACHABLE/ADMIN_PROHIBITED make_resource_exhausted icmpv6.py:407 (tested via no_silent_drops.json) never invoked on a drop path. Rs: doc comments only forward_buffer.rs:30,107, stack.rs:90,695 | high — flagged; pre-authorized bead if lowercase musts count |
| R-ABF-012 | No silent drops: return error to local sender (Design Principles 5) | implemented+tested | Same sites as R-ABF-001/010; no_silent_drops.json tx_queue_full_raises_exception consumed by Py routing/test_no_silent_drops_vectors.py + timing/test_tx_queue_vectors.py | high |
| R-ABF-013 | No silent drops: log queue-full events for diagnostics (Design Principles 5) | implemented+tested | Py: warning on preemption link/tx_queue.py:129, eviction warning forwarding_buffer.py:223 + router.py, backpressure debug :193; test_eviction_logged_at_warning (test_no_silent_drops_vectors.py). Rs: warn! on QueueFull lichend.rs:555-558,586-589. C: LOG_WRN on push failure at the wired site lora_l2_tx.c:409-410; tx_queue.c itself is stats-only (no log statements); unwired C fwd buffer unlogged | high |
| R-ABF-014 | queue_stats fields: packets_queued, packets_dropped_deadline, packets_dropped_full, max_latency_ms, avg_latency_ms (Measuring Queue Latency) | implemented+tested | Rs TxQueueStats tx_queue.rs:406-427 (+packets_preempted) with tests stats_tracking/packets_dropped_full_counter/latency_tracking_basic/max/latency_ewma_smoothing :962-1488; Py TxQueueStats timing/tx_queue.py:98-108 + link/tx_queue.py:174-191 + vector stats_track_latency (tx_queue_bounded.json:199-205); C tx_queue_stats tx_queue.h:108-121 + /status/queues encoder emits exactly the 5 spec keys status_cbor.c (Rs client doc status.rs:181-183) | high |
| R-ABF-015 | Expose queue stats via /status/queues CoAP resource (Measuring Queue Latency) | implemented+untested | C gateway: Observable resource {"status","queues"} apps/gateway/src/main.c:504-601 + encoder status_cbor.{h,c}:17-50; no C test (gateway_status suite lacks queues; rg encode_queues → apps only). Rs client: paths.rs:25 STATUS_QUEUES + QueueStats::from_cbor status.rs:186-215 + test queue_stats_decode_firmware_map :404 (oracle = mirrored firmware keys, not C encoder bytes). Py: absent both sides | high |
| R-ABF-016 | Bufferbloat avoidance must be tested under congestion: 5 scenarios (Testing) | divergent | Oracle bufferbloat_congestion.json pins all 5 (literals from spec) asserted Rs bufferbloat_vectors.rs:105-146 + Py test_bufferbloat_congestion_vectors.py. Scenarios 1-3 (queue-full/deadline/preemption) have real tests in all stacks (R-ABF-001/005/009). Scenario 4 multihop_latency (e2e delay bounded under load): expectation string only, no multi-hop latency-under-load test anywhere. Scenario 5 fairness: per-source unit tests only (R-ABF-003), no under-load test — and the mechanism is unwired, so one could not pass today | high — flagged |

### Histogram (rows)

- implemented+tested: 10 (R-ABF-001, 002, 004, 005, 006, 008, 010, 012, 013, 014)
- implemented+untested: 1 (R-ABF-015)
- divergent: 4 (R-ABF-003, 007, 009, 016)
- not-implemented: 1 (R-ABF-011)
- ambiguous: 0

### Gap beads filed (0; cap 10; overflow 0)

No capitalized RFC 2119 MUSTs exist in this appendix, so no gap beads are due
per the matrix preamble (consistent with the spec/08-nodes and
spec/01-architecture sweeps). The divergences are recorded above and in
`docs/spec-coverage-appendix-bufferbloat-flagged.md`, which also carries the
section-level question (do the lowercase "must"s at spec lines 90/175 carry
normative force?) and pre-authorized bead text for R-ABF-003 (forwarding
buffer unwired in all three stacks), R-ABF-011 (NACK never sent), and
R-ABF-016 (congestion scenarios 4-5 untested) should Opus rule them
MUST-gaps. No pre-existing beads were duplicated by this sweep.
