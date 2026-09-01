# Opus verification pass — spec coverage sweep

You are the VERIFICATION pass for a requirements-coverage sweep of the LICHEN
protocol spec. A cheaper model performed the extraction and classification;
your job is to independently verify its judgments where errors are likely or
consequential. The project threat model: radio adversary only (replay,
forgery, downgrade, key establishment over the air). NO side-channel or
zeroization concerns — never introduce or flag them.

For each flagged requirement below:
1. Read the spec text yourself (section file given).
2. Check the cited implementation evidence (file:line) and the cited test.
3. Rule: CONFIRM (classification correct), CORRECT (new classification +
   evidence), or ESCALATE (genuinely ambiguous — say what evidence would
   resolve it and which maintainer context is needed).
4. For any requirement you downgrade from implemented to gap: state exactly
   what is missing.

Rules: evidence only — no agreement without checking the code or test. Do not
edit source code. Do not file beads (the integration pass does that). Report
per-requirement verdicts in the same order as the flagged list, plus a final
tally: confirmed / corrected / escalated.

## Adjudicated decisions

Before verifying, read `spec/decisions.jsonl`. Each line records a FINAL
human decision. If any flagged requirement conflicts with a recorded
decision, the decision wins — CONFIRM the decision's position regardless
of what the spec text or prior classification said. Do not ESCALATE or
CORRECT against a recorded decision.
