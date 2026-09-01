# Spec Coverage Sweep — per-section extraction protocol (flash pass)

You are performing the requirements-extraction pass for ONE section of the
LICHEN protocol spec. The .beads/ directory is the live shared store — NEVER
stage or commit it. You MAY edit only `docs/spec-coverage.md` and file beads.

INPUT: the spec section file given to you (e.g. spec/05-routing.md).

## Step 0 — Check adjudicated decisions

Before starting the sweep, read `spec/decisions.jsonl`. Each line is a
JSON object recording a human-adjudicated design decision. For each decision
whose `specs` array includes the section you are sweeping:

1. Run the `verify.grep` check (if present): the pattern MUST match in the
   specified file. If it doesn't, the spec has regressed — **fix the spec
   file to match the decision** before proceeding with the sweep.
2. Run the `verify.grep_absent` check (if present): the pattern MUST NOT
   appear in the specified file. If it does, the spec has regressed — fix it.
3. If a decision's `verify` target is a source file (not a spec file), verify
   it but do not modify source — file a bead if it has regressed.

Decisions in this file are FINAL. Do not re-adjudicate them, question them,
or file beads that contradict them. If a requirement in the spec text
conflicts with a recorded decision, the decision wins and the spec text
should be updated to match.

## Step 1 — Extract

Walk the section top to bottom. Extract every normative requirement
(MUST / MUST NOT / SHOULD / SHOULD NOT / MAY where it defines behavior).
Number them: R-<section>-NNN (e.g. R-05-001). For each record:
- the verbatim requirement text (trim to one sentence if long)
- the spec section/heading it appears under

## Step 2 — Map to implementation

For each requirement, find evidence in the codebase:
- `rg` across rust/, lichen/, python/src/, firmware/ for the implementing
  symbols (function names, constants, config options, packet structures)
- find test evidence: test/vectors/*.json, lichen/tests/*, python/tests/*,
  rust/*/tests/*
Classification (exactly one):
- **implemented+tested** — code exists AND a test covers it (name the test)
- **implemented+untested** — code exists, no test found
- **divergent** — code exists but behaves differently than the spec text
- **not-implemented** — no evidence found
- **ambiguous** — you cannot tell; say exactly what is unclear
Mark every classification with evidence: file:line for code, test name for
tests. No evidence = ambiguous, not implemented.

## Step 3 — Coverage matrix

Append to docs/spec-coverage.md a section:

    ## <spec file> — coverage (sweep <date>)
    | Req | Spec text (trimmed) | Status | Evidence | Confidence |

Group rows that share one implementation site, but every MUST keeps its own row.
Set Confidence: high/low. low = you would want a second opinion.

## Step 4 — Gap beads

For each **not-implemented** or **divergent** MUST: file a bead
`bd create --parent <epic> --label <area> --label spec-gap ...` with the
requirement text, the classification evidence, and suggested placement.
CAP: 10 gap beads per section. If more than 10 MUST-gaps exist, file the 10
most impactful and note the overflow count in the matrix. SHOULD-gaps: file
only if the omission breaks a documented feature; otherwise note in matrix.
MAYs: never file. oscore/EDHOC semantics: label `human-only`, never plan a fix.

## Step 5 — Flagged set for Opus verification

Write docs/spec-coverage-<section>-flagged.md: every requirement where
(a) confidence was low, (b) classification was ambiguous or divergent, or
(c) the section is 06-security or concerns oscore/EDHOC semantics.
For each: the requirement, your classification, your evidence, and the
specific question Opus should answer.

## Step 6 — Report

Print: requirements extracted, classification histogram, gap beads filed,
flagged count, and the matrix section location.
