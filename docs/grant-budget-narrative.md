<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Budget Narrative — LICHEN 500-Node Conference Deployment

*Companion to `prfaq-500node-deployment.md` ($28,500 total). For grant
applications; customize the "funder fit" column per application.*

## Total request: $28,500

| Line item | Amount | Justification |
|---|---:|---|
| Node hardware: 500 × Seeed T-Echo | $22,500 | ~$45/unit landed. nRF52840 + LR1110 (LoRa + GNSS) + e-ink. Chosen for built-in GPS (TDMA time discipline), Meshtastic-compatible form factor for easy reflash, and a vendor with stable bulk availability. Bulk pricing negotiated with LilyGO. |
| Gateways, flash jigs, SDR instrumentation | $2,500 | 4× Raspberry Pi 5 + RAK2287 (SX1302 multi-channel) concentrator HATs as border routers; USB flash jigs for 500-node staging; one SDR for over-the-air capture/debugging of the live mesh. |
| Shipping and logistics | $2,500 | Consolidated freight to three conference venues, staging-site transfers, and return shipping for post-event refurbishing. |
| Tariffs and duties | $1,000 | International components crossing borders (Radios/antennas from CN, EU conference entry). |
| Contingency and booth logistics | $2,000 | Venue table/booth fees, printed quick-start cards for attendees, replacement stock for damaged units. |

Landed cost per node: **$48**. Post-event resale at **$75+** recovers
approximately $18,750 (66%+), making each future deployment self-seeding.

## What the grant funds

Grant funding covers the capital costs (hardware, gateways, logistics). Project
labor — firmware, gateway stack, simulator, protocol spec, test vectors,
deployment operations — is contributed and already largely built. This makes the
grant unusually capital-efficient: reviewers fund measurable deployment outcomes,
not speculative development.

## Cost recovery

- Resale proceeds roll into the next deployment (500 → 2000 nodes).
- All procurement documents (quotes, BOM, flash-jig designs) are published so
  other communities reproduce the deployment at the same unit economics.

## Funder fit notes

| Funder | Request framing | Notes |
|---|---|---|
| NLnet / Open Internet Stack | €5k–€50k range; fund the deployment as validation of open Internet standards on low-power radio; emphasize standards, libre licensing, public datasets | Calls reopen 2026-09-03, deadline 2026-11-03 12:00 CEST. Request may be scoped to the deployment plus IETF draft work. |
| ARDC | Hardware and education/outreach: amateur-radio framing (ham-band operation, emergency-communications resilience, on-site education at conferences); ARDC's 2026 portfolio already includes Meshtastic network expansions and LoRa mesh enhancements | Rolling applications via contact@ardc.net. |
| Open Technology Fund | Censorship-resistant off-grid communications angle | Weaker narrative fit; apply only if Tier-1 funders decline. |

## Reporting

Each funded deployment produces: a public post-conference performance report
(packet statistics, density handling, failure analysis), updated open-source
release, and per-node resale accounting. Funders receive the report and are
credited in the repository README and conference talk.
