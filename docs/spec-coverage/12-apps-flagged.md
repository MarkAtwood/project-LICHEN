<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

## spec/12-apps.md — flagged for Opus verification (sweep 2026-09-01)

### R-12-008 — ts wall_clock_valid gating (18.1.1)
- Classification: divergent (low confidence)
- Evidence: `from` is rebound to transport identity (messaging.py:339-348); no wall_clock_valid gate on sending, no documented acceptance of ts=0 as "time unknown".
- Question: Is ts-gating implemented elsewhere (e.g. a time-provider module feeding messaging), or should this be a gap bead? Does any implementation accept `ts=0`?

### R-12-009/010/011/012/013 — store-and-forward cluster (18.1.4)
- Classification: not-implemented / divergent
- Evidence: no `/msg/store` resource; fair-share eviction and 4.03/4.00 back-pressure forms absent; 4.13/5.03 triggers differ from spec.
- Question: Is S&F intentionally deferred (DTN dead-drop in 18.9 may be the realized substitute), or a genuine gap? If S&F is superseded by deaddrop, should the spec say so?

### R-12-018 — Observe position notification triggers (18.2.3)
- Classification: implemented+tested, low confidence
- Evidence: Observe plumbing exists (senml.py:54, position_observe.json) but no evidence of distance-threshold (50 m) or time-interval notification triggers.
- Question: Are movement-threshold notifications implemented anywhere, or is every position change notified?

### R-12-019/020 — position privacy divergence (18.2.4)
- Classification: divergent
- Evidence: Python lacks `off` privacy mode (position_privacy.py:23-28); Python 4.01 policy not wired into `SenMLLocationResource.render_get` (senml.py:110-113) so the live resource does not enforce authentication; C enforces.
- Question: Confirm Python divergence is a real spec gap (not covered by a site-level auth wrapper I missed), and whether "off" mode omission is intentional.

### R-12-029 — silent drop of unsigned SOS (18.4.1)
- Classification: divergent (low confidence)
- Evidence: C drops silently (sos_origin.h:19); Python returns 4.01 (emergency.py:237-238).
- Question: Does the Python 4.01 response violate the spec's silent-drop anti-enumeration requirement, or is 4.01 acceptable at the CoAP layer while the link layer drops silently?

### R-12-039 — GET /sos active emergencies (18.4.5)
- Classification: implemented+untested (low confidence)
- Evidence: C stub (coap_server.c:560-575), Py emergency.py:197-200.
- Question: Is the C path a full implementation or a stub that returns placeholder state?

### R-12-049 — multicast roll call (18.6.2)
- Classification: divergent (low confidence)
- Evidence: unicast POST /rollcall implemented (emergency.py:413-452); `[ff02::mesh]` multicast target not evidenced.
- Question: Does any layer support multicast POST for rollcall, or is multicast addressing itself deferred to a routing-layer epic?

### R-12-051 — /config/checkin (18.6.4)
- Classification: divergent (low confidence)
- Evidence: C only (checkin_resource.c:341-383); no Python/Rust.
- Question: Is per-language parity for this config resource planned, or is C-only acceptable per the feature matrix?

### R-12-055 — traceroute C-side absence (18.7.4)
- Classification: implemented+tested (low confidence)
- Evidence: Python + Rust implement; no C traceroute resource found.
- Question: Confirm C traceroute absence and whether the embedded node is expected to serve or only forward traceroute.

### R-12-064 — voluntary group leave (18.8.2)
- Classification: divergent
- Evidence: DELETE /groups/{gid} is owner-only authoritative delete (groups_collection.py:713-731); members get 4.03.
- Question: Spec says member voluntarily leaves via DELETE on own node; Python models DELETE as owner delete. Which semantic is intended — should member self-leave be DELETE on the member's own node?

### R-12-076 — delegation chain verification at CoAP layer (18.8.6)
- Classification: divergent (low confidence)
- Evidence: `verify_delegation_token` exists (delegation_tokens.py:317-398) but no resource calls it; no seq cache caller.
- Question: This is covered by gap bead (token endpoints); Opus should confirm no other caller exists (e.g. in lichen-node dispatch or Zephyr C).

### R-12-077 — deaddrop SCHC compliance (18.9)
- Classification: implemented+untested (low confidence)
- Evidence: SCHC pre-provisioned rules cited; deaddrop vectors exercise OSCORE/CBOR but no SCHC-compressed deaddrop vector was found.
- Question: Do SCHC vectors for /deaddrop exist under another name (appendix-schc vectors), or is this requirement untested?

### R-12-096 — link-format 40 content format (18.12)
- Classification: implemented+untested (low confidence)
- Evidence: CBOR 60 / senml 112 pervasive; link-format 40 found only in discovery tests.
- Question: Confirm resource discovery responses use Content-Format 40 as the summary table requires.
