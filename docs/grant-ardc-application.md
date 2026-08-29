<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# ARDC Grant Application Draft — LICHEN 500-Node Conference Deployment

*Draft for submission to Amateur Radio Digital Communications (rolling;
contact@ardc.net). Companions: `grant-budget-narrative.md`,
`grant-technical-description.md`, `prfaq-500node-deployment.md`.
Requires owner review and explicit authorization before sending.*

---

**Project title:** LICHEN — a standards-based LoRa IPv6 mesh: 500-node
amateur-radio deployment and public performance study

**Requested amount:** $28,500 (hardware, gateways, logistics — see budget
narrative; approximately 66% recovered through post-event resale and rolled
into subsequent deployments)

**Applicant:** [Mark Atwood / LICHEN project]

## Summary

LICHEN is an open-source (GPL-3.0) protocol bringing genuine IP networking —
native IPv6, IETF-standardized compression (SCHC), routing (RPL), and security
(OSCORE/EDHOC) — to sub-$50 LoRa hardware compatible with the Meshtastic
ecosystem. Three independent implementations (embedded C on Zephyr, Linux
gateways in Rust, a Python reference) are held in conformance by a shared,
public test-vector suite.

We request ARDC support for the project's first large-scale, real-world
deployment: a 500-node amateur radio mesh operated across three major hacker
conferences, with full public documentation of design, operation, and measured
performance.

## Amateur radio alignment

- **On-air operation:** nodes operate under amateur radio licenses in
  conference-hosted stations and with individually licensed attendees; the
  deployment doubles as a large-scale demonstration of modern digital modes
  (LoRa CSS with TDMA channel access) for new and returning licensees.
- **Emergency-communications resilience:** the protocol's design priorities —
  decentralized trust (no network-wide secrets), automatic RPL failover,
  store-and-forward messaging, and SOS priority alerting — mirror ARES/RACES
  requirements for infrastructure-independent communication. The deployment's
  public performance report will document exactly these behaviors under load.
- **Education and outreach:** every attendee node is a hands-on lesson in
  IP networking over radio. Flash jigs, bills of materials, and a logistics
  runbook will be published so clubs can reproduce the deployment; conference
  talks will present the architecture and results.
- **Prior art in ARDC's portfolio:** the foundation's 2026 grants include
  multiple community LoRa/Meshtastic mesh expansions; LICHEN extends this line
  of work from proprietary meshes to an open, standards-based alternative with
  published specifications and cross-vendor implementations.

## Technical merit

The protocol is implemented and continuously validated today: link-layer
security with key-derived IPv6 addressing, RPL non-storing routing with
multi-gateway failover, SCHC header compression, OSCORE end-to-end object
security, and CoAP services (messaging, position, SOS, presence). The
conference environment is chosen deliberately: it is the density-and-adversity
regime (50+ nodes/km², RF noise, uncoordinated devices, gateway failures) where
mesh protocols actually break, and where a documented pass/fail has lasting
engineering value.

## Deliverables and public benefit

1. 500 operational nodes in attendees' hands, reflashed to open firmware —
   a durable seed of open protocol literacy in the community.
2. Public performance dataset and post-conference report: density handling,
   packet loss, convergence times, failure analyses. No comparable public
   dataset exists for any LoRa mesh protocol at this scale.
3. Internet-Draft submissions for the protocol's novel, generally applicable
   elements (truncated Schnorr link signatures, key-derived addressing).
4. Complete reproduction kit: firmware, gateway stack, simulator, BOMs,
   flash-jig designs, runbook — everything a club needs to run its own mesh.
5. Conference talks and a written runbook aimed at club-level adoption.

## Budget summary

$28,500 total: $22,500 node hardware (500 × T-Echo at ~$45 landed), $2,500
gateways/flash jigs/SDR instrumentation, $2,500 shipping and logistics, $1,000
tariffs, $2,000 contingency and booth logistics. Grant funds capital only; all
engineering labor is contributed. Post-event resale at $75+ per node recovers
the majority of hardware cost and funds the next, larger deployment.

Full line-item justification is provided in the attached budget narrative.
