# Credit-floor gate + wave runner for the heft fleet

## Credit-floor gate (burn control)

The beads-loop plugin must check OpenRouter remaining credits before
submitting each round. Implementation in `.opencode/plugins/beads-loop.tsx`:

- Add a `creditsRemaining()` helper: read `~/.config/opencode/opencode.json`,
  extract the openrouter `apiKey` (starts with `sk-or-`), curl
  `https://openrouter.ai/api/v1/credits`, return `total_credits - total_usage`.
  Cache the result for 10 minutes (avoid hammering the API per round).
- In `maybeRound()`, after `readyCount()`: if `creditsRemaining() < 50`
  (FLOOR constant), do NOT submit the round. report() a warning:
  "credit floor hit — fleet idle until top-up". Workers stay alive but idle.
- When credits recover (auto-topup fires), the next idle tick resumes rounds
  automatically.

Floor constant: 50 (leaves ~3.5h of review+implementation spend after the
warning, and the auto-topup at $15 replenishes before the $10 hard floor).

## Wave runner (spec coverage sweep)

`scripts/spec-sweep-all.sh`:
- Section list ordered by requirement density (09-packets-timing first).
- Skips sections whose matrix file already exists (resumable).
- Credit-gates before each section (floor from arg, default 150 for the
  sweep — sweeps are Opus+flash, more expensive per unit than worker rounds).
- Per section: flash extraction (spec-sweep.sh) → matrix file
  docs/spec-coverage/<section>.md → Opus verification of the flagged set
  (opus-verify-prompt.md + flagged file) with output logged.
- Commits coverage files per section; pushes via the sync loop's auto-push.

## Fleet pause/resume for the dep-bump windows

When oscore 0.1.3 lands (zlrx), the fleet pauses briefly: the sync loop's
reclaim + workers' claim cadence handles it — no special action.

## Watch cadence (unattended)

- burn.log: hourly entries (log-burn via sync loop)
- .beads-sync.log: conflicts + merges per cycle
- fleet-debug.log: loop plugin trace
- docs/spec-coverage/: matrix growth per wave
