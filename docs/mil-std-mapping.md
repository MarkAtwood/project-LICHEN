<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Development in MIL-STD-2167A/498 Terms

Status: descriptive mapping, not a compliance claim. This document
translates how LICHEN is actually built into the vocabulary of
MIL-STD-2167A (1988) and MIL-STD-498 (1994), for readers whose formative
software experience was under those standards — and for anyone who wants
to see what a 1990s defense software lifecycle looks like when the
contractor is an agent fleet.

LICHEN claims no formal conformance to any military standard. Nothing in
this document changes LICHEN process, artifacts, or structure.

## 1. The analogy in one paragraph

LICHEN is a defense-style software development where every human role
except one has been replaced by autonomous agents. The one remaining
human is the cognizant engineer, contracting officer's representative,
and configuration control board simultaneously. All the 2167A/498
deliverables exist — requirements, design, traceability, V&V,
discrepancy tracking, configuration management, audits — but they are
generated and maintained as machine-readable artifacts by the agents
that also produce the code, and the lifecycle is continuous rather than
gated by formal reviews.

## 2. Roles mapping

| 2167A/498 role | LICHEN occupant |
|---|---|
| Contracting agency (government) | The project owner ("Mark") |
| Cognizant engineer / COR | The project owner, during session interaction |
| Configuration Control Board | The project owner + `spec/decisions.jsonl` (frozen adjudications) |
| Prime contractor | The agent fleet (7-8 worker agents + 1 hard-problem lane) |
| Systems engineering | Spec coverage sweep agents; the decomposition agent (Astra) |
| Software engineering | Worker agents (GLM-5.3-Flash, one GPT-5.6-Luna) |
| IV&V agent (independent) | 3× independent code review passes (Kimi K3, a different model than implementers) |
| QA / discrepancy reports | The beads tracker (`bd`), every finding filed as an issue |
| Configuration management | Git, the sync loop, the merge janitor, and the pre-commit store hook |
| Auditors | Autonomous guards (outcome canary, waste alarm, stall detector) + the planned end-to-end critique pass (Astra) |

Note the structural difference from 2167A: IV&V there was *contractually*
independent; here it is *architecturally* independent — reviewers are a
different model family than implementers, and adjudication authority is
held only by the human.

## 3. Deliverables mapping

| 2167A/498 deliverable (DID) | LICHEN artifact |
|---|---|
| SRS — Software Requirements Specification (DOD-STD-7935) | `spec/01` through `spec/19` + appendices; normative RFC-2119 statements with `R-<sec>-NNN` identifiers assigned during the coverage sweep |
| IRS — Interface Requirements | Spec sections on framing (02), SCHC (03-adaptation), CoAP/LCI (11), GCP (08) |
| SDD — Software Design Document | The spec set itself is design-level; implementation-guidance lives in `spec/10-implementation.md` and per-module docs |
| Source code & unit-level docs | Three co-equal implementations: Rust (`rust/`), Zephyr C (`lichen/`), Python reference (`python/`) |
| STP/STD — Test Plans & Procedures | Test suites colocated with each implementation |
| Test data | `test/vectors/` — canonical JSON vectors with family schemas, generated from independent oracles, cross-implementation bit-exact |
| Traceability matrices | `docs/spec-coverage/*.md` — every R-number mapped to evidence (file:line, test name, vector) across all three implementations, with status and confidence |
| FCA/PCA — Functional/Physical Configuration Audit | The planned end-to-end "grok and critique" pass |
| Discrepancy reports (DR) / SFR — Software Failure Reports | Beads issues (type `bug`), with priority 0-4, evidence, and mandatory closure gates |
| CCB minutes / change requests | `spec/decisions.jsonl` (machine-readable adjudications) + `.beads` event logs (append-only) |
| SCM plan | `AGENTS.md`, the fleet operating scripts (`scripts/`), git branch-per-worker topology |
| SPM — Software Project Management data | `bd stats`, coverage matrices, the fleet's own operational history |
| IV&V reports | The 3× code review outputs (findings filed as beads before merge) |

## 4. Process mapping (498 activities)

| MIL-STD-498 activity | LICHEN practice |
|---|---|
| 5.1 Project planning | Continuous, not phase-gated; the queue (ready beads) *is* the plan |
| 5.2 System requirements analysis | Spec coverage sweep: requirements extraction, evidence mapping, gap filing (capped 10 gap-beads/section) |
| 5.3-5.5 Requirements → design → implementation | One agent round-trip: claim bead, implement, test, review, close, commit (~15 min/bead, one P0-P2 bead per round, up to 5 P3/P4 batched) |
| 5.8 Unit/CSM testing | Tests mandatory before close; cross-implementation vector parity required (bit-exact across Rust/C/Python) |
| 5.10-5.11 Integration & V&V | Merge pipeline: rerere-replayed resolutions → per-file LLM semantic merge (Kimi K3) → janitor escalation → build/test gates |
| 5.12-5.13 Delivery & installation | Continuous: every merge to main is a delivery; gates (clippy, pytest, host C suites) run per-merge |
| 5.14-5.17 Configuration management | Git; per-worker branches merged by the sync loop; the beads store is main-only, enforced by pre-commit hook; frozen adjudications in `decisions.jsonl` |
| 5.18-5.20 Reviews & audits | Every merge carries 3× independent review; the outcome canary audits the *fleet* hourly-class; full-corpus critique pass planned post-"soft done" |
| 5.21 Risk management | The guards: stall detection, circuit breakers on repeat-failure beads, waste alarm, escalation to human only for adjudication-type decisions |

## 5. The four-way trace, LICHEN edition

2167A's famous chain — requirement → design → code → test — exists here
as a *queriable* structure rather than a maintained document:

- **Requirement**: `R-08-006` in `spec/08-gateway-coordination.md`
  ("All cooperating gateways use same RPLInstanceID...")
- **Design**: the multi-instance architecture sections of the same spec
  (spec is design-level)
- **Code**: `rust/lichen-node/src/multi_instance.rs:320-958`,
  `lichen/subsys/lichen/rpl/rpl_multi_instance.c:22-351`,
  `python/src/lichen/rpl/multi_instance.py:137-657` (three
  implementations, co-equal by policy)
- **Test**: `test/vectors/rpl_multi_instance.json` (13 vectors) +
  `rust/.../multi_instance_vectors.rs` + `python/tests/rpl/...` —
  bit-exact across all three

The coverage matrices hold this chain per requirement. The sweep runner
regenerates them when spec drifts (staleness detection by mtime), which
is the answer to the failure mode every 2167A survivor remembers: the
trace document that became a lie maintained for auditors. Here the trace
is rewritten by agents from source truth, and the planned critique pass
audits whether the trace is *true*, not merely present.

## 6. Where the analogy holds, and where it breaks

Holds:
- Normative language discipline (RFC 2119 in spec, "shall" equivalents)
- Numbered, atomic requirements with unique IDs
- Trace to three implementations and their tests
- Discrepancy tracking with mandatory closure
- Configuration control with frozen baselines (`decisions.jsonl`)
- Independent review before integration
- Audit as a distinct activity with distinct tooling

Breaks (deliberately):
- **No phase gates.** SRR/PDR/CDR collapse into continuous operation;
  the "reviews" run per-merge, not per-milestone.
- **The CCB is one human plus a frozen record.** Adjudications are rare,
  logged, and final — the fleet is forbidden from relitigating them
  (enforced by the escalation rules in `AGENTS.md`).
- **Three implementations instead of one.** Not redundancy for
  reliability — a *conformance device*: when two implementations
  disagree, the spec (not either implementation) is the arbiter, and the
  disagreement itself is a discrepancy report.
- **The deliverables are the process.** There is no document written
  "for the review" that then rots; every artifact is load-bearing in the
  loop (the matrices drive gap filing; the vectors gate merges; the
  beads drive the work queue).
- **Audit is continuous and automated.** The outcome canary, waste
  alarm, and stall detectors are the "government QA" that never sleeps —
  and their alarms file their own discrepancy reports.

## 7. The historical note this document exists for

MIL-STD-2167A's traceability apparatus cost a fortune in the early 90s
because every link in the chain was maintained by hand, and the chain
went stale between audits. LICHEN's version keeps the chain — the
numbered shalls, the evidence mapping, the discrepancy discipline, the
frozen baselines — and automates every link of it, including the
regeneration and the audit. The lesson of 2167A wasn't that traceability
was wrong; it was that traceability at human maintenance speed is a lie.
The fleet is the correction: trace at machine speed, audit at machine
speed, and reserve the humans for the one thing machines in this project
are forbidden to do — decide what the system shall do.
