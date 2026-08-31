<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Spec coverage flagged set — spec/appendix-c-safety.md (sweep 2026-08-31)

Companion to the `spec/appendix-c-safety.md — coverage (sweep 2026-08-31)`
section in `docs/spec-coverage.md`. Every row below is (a) low confidence,
(b) classified ambiguous or divergent, or (c) a scope/normativity question the
matrix could not resolve. Gap beads already filed from this sweep are named
inline; the questions here are for verification, not new bead generation.

This appendix is a build/CI policy section, not a wire-protocol section, so
"verified" means confirming the build/CI evidence, not running test vectors.

---

## F1. R-APPC-001 — Basic hardening flags vs "NO EXCEPTIONS. NO WAIVERS."

- **Requirement:** "All C code MUST be compiled with these flags" (incl.
  `-Werror`, `-Wconversion`, `-fstack-protector-strong`); preamble: "NO
  EXCEPTIONS. NO WAIVERS. NO 'FIX IT LATER.'"
- **Classification:** divergent (all deviations documented in-file)
- **Evidence:** `lichen/zephyr/CMakeLists.txt:48-135` implements the full flag
  set on every lichen module library target (:169-185); host tests via
  `lichen/tests/cmake/test_common.cmake:56-63`. Deviations: `-Wno-error=conversion`
  (:71, TODO to promote at :68), `-Wno-error=cast-align` (:78, upstream nrfx/
  Zephyr headers), `-Wno-error=duplicated-branches` (:110, cbprintf internals),
  `-Wno-error=cpp` (:125); `-fstack-protector-strong` not passed raw — routed
  through `CONFIG_STACK_CANARIES` (:115-118; Zephyr emits
  `-fstack-protector-all`); per-file exemptions: lr1110 driver
  (`lichen/drivers/lora/lr1110/CMakeLists.txt:22`), monocypher
  `-Wno-error=stack-usage` (`lichen/subsys/lichen/crypto/CMakeLists.txt:13-19`).
- **Bead:** `project-LICHEN-worker6-b7z9.51`
- **Question for Opus:** Does the spec's absolute "NO WAIVERS" language make
  these documented in-code waivers a spec violation to be burned down (delete
  `-Wno-error=` lines after fixing findings), or should the spec text be
  amended to ratify them? Sub-question: is routing
  `-fstack-protector-strong` through `CONFIG_STACK_CANARIES` (which uses
  `-fstack-protector-all`) an acceptable — or stronger — equivalent?

## F2. R-APPC-002 — Advanced hardening is partially implemented and dormant

- **Requirement:** "When toolchain supports it, enable these advanced
  protections" (`-fsanitize=cfi -fvisibility=hidden`, `-fbounds-safety`,
  `-fsanitize=safe-stack`) — keyword-less conditional imperative under a
  "Compiler Hardening (Mandatory)" umbrella.
- **Classification:** implemented+untested (CFI only); rest not-implemented
  (conditional precondition unmet)
- **Evidence:** `lichen/zephyr/CMakeLists.txt:141-154` enables CFI only under
  Clang >= 18; the project builds with the GCC-based Zephyr SDK 0.16.8, so the
  branch is dormant and untestable. `-fbounds-safety` / `-fsanitize=safe-stack`:
  zero hits repo-wide.
- **Question for Opus:** Is "when toolchain supports it" satisfied by the code
  path existing (current state), or should CI add a Clang-18+ cross-build job
  to actually exercise the CFI branch? Should the spec downgrade
  `-fbounds-safety`/`safe-stack` to a future-work note?

## F3. R-APPC-003 — Pointer annotations "where applicable" is unverifiable

- **Requirement:** "All new code MUST use bounds annotations where applicable."
- **Classification:** implemented+untested (low confidence)
- **Evidence:** Annotations used in 15+ files (`lichen/subsys/lichen/hal/include/lichen/hal.h`
  23 matches, `gcp/include/lichen/gcp_trust.h` 25, `oscore/include/lichen/edhoc.h`
  33, `schc/include/lichen/schc.h` 9, `link/include/lichen/tx_queue.h` 18,
  `oscore/oscore_ctx.c` 19). No CI mechanism checks "all new code"; GCC (the
  actual firmware toolchain) ignores `_Nonnull`/`__counted_by` in most cases.
- **Question for Opus:** What enforcement, if any, should back this MUST — a
  clang-tidy check, a review checklist item, or spec amendment to
  "SHOULD/encouraged"? Note the oscore/EDHOC annotation sites carry the usual
  high edit bar (label `human-only` if a change lands there).

## F4. R-APPC-007/008 — Thread analyzer and heap validation: gap or scoped-out?

- **Requirement:** "All firmware builds MUST enable in prj.conf: …
  CONFIG_THREAD_ANALYZER=y, CONFIG_THREAD_ANALYZER_USE_PRINTK=y,
  CONFIG_THREAD_ANALYZER_AUTO=n (CI and debug builds) … CONFIG_SYS_HEAP_VALIDATE=y
  (debug builds)."
- **Classification:** not-implemented (zero hits repo-wide)
- **Evidence:** `rg CONFIG_THREAD_ANALYZER|CONFIG_SYS_HEAP_VALIDATE` over
  `lichen/` and `firmware/` .conf/Kconfig: zero. The other flags from the same
  MUST sentence are present (`lichen/apps/gateway/prj.conf:54-57`,
  `lichen/apps/puck/prj.conf:62-65`, `firmware/bridge-zephyr/prj.conf:40-43`,
  `lichen/tests/util/prj.conf:10-13`).
- **Bead:** `project-LICHEN-worker6-b7z9.49`
- **Question for Opus:** The spec block qualifies the thread analyzer with
  "(CI and debug builds)" and heap validation with "(debug builds)". Do these
  parentheticals scope the MUST to test/debug configurations only (making the
  app prj.confs conformant and the bead a test-config-only task), or is the
  MUST unconditional ("All firmware builds MUST enable in prj.conf") and the
  parentheticals merely descriptive? This decides the bead's placement.

## F5. R-APPC-009/013 — native_sim sanitizer + fuzz CI wiring is orphaned

- **Requirement:** R-APPC-009: "All tests run on native_sim MUST use
  AddressSanitizer and UndefinedBehaviorSanitizer." R-APPC-013: "All code that
  parses untrusted input MUST be fuzz-tested" (frame.c, schnorr48.c, schc.c).
- **Classification:** divergent (both)
- **Evidence:** `lichen/tests/sanitizers.conf` exists with
  `CONFIG_ASAN=y CONFIG_UBSAN=y` (header cites the policy) but is referenced by
  nothing — no prj.conf, no CI `EXTRA_CONF_FILE` (only `renode_console.conf`
  is ever passed). `lichen/tests/fuzz/` has all three harnesses
  (`fuzz_frame.c:22`, `fuzz_schc.c`, `fuzz_schnorr48.c`) and a CMakeLists with
  `-fsanitize=fuzzer` support, but no `testcase.yaml`/`prj.conf`, so the
  nightly job (`.github/workflows/fuzz.yml:96-144`, `if: schedule` :99) runs
  twister over a directory that discovers zero tests; `ci.yml` has no fuzz
  job. Standalone host CMake tests comply (`test_common.cmake:18-19,69-86`).
- **Bead:** `project-LICHEN-worker6-b7z9.50` (shared fix site)
- **Question for Opus:** (a) Confirm the fix shape: `testcase.yaml` + `prj.conf`
  including `sanitizers.conf` under `lichen/tests/fuzz/`, so twister builds and
  runs all three harnesses on sanitized native_sim. (b) Does "MUST be
  fuzz-tested" require PR-gated execution, or is a nightly schedule run
  sufficient once it actually runs? (c) Hygiene: committed build debris under
  `lichen/tests/fuzz/build/` (incl. `a.out`) and stray `*.o` files — route to
  the regular review loop or fold into bead .50?

## F6. R-APPC-010 — clang-tidy: config drift + 50-file CI scope

- **Requirement:** "All C code MUST pass clang-tidy with this configuration"
  (exact checks list; WarningsAsErrors '*'; CI command over
  `lichen/subsys/lichen/**/*.c lichen/lib/**/*.c lichen/drivers/**/*.c`).
- **Classification:** divergent
- **Evidence:** `lichen/.clang-tidy` exists citing the policy (:5) with
  `WarningsAsErrors: '*'` (:63), but adds six documented suppressions beyond
  the spec list (:32,35,37,38,39,40) and contains a contradictory duplicate
  (`cppcoreguidelines-pro-bounds-pointer-arithmetic` enabled :15, disabled :41
  — later entry wins). CI scope: `.github/workflows/ci.yml:130-136` —
  `find … | head -50` (first 50 files only) with `-p /dev/null` (no compile
  database). Local `scripts/lint-c.sh:63-76` covers all subsys/lib/drivers
  files.
- **Bead:** `project-LICHEN-worker6-b7z9.47`
- **Question for Opus:** (a) Is the curated `.clang-tidy` (stricter superset
  with documented, ratcheted suppressions) an acceptable interpretation of
  "this configuration", or must the spec's literal YAML be restored? (b) Is
  the `head -50` CI cap a hard violation to fix now (full file list +
  `compile_commands.json`), given the local script already covers everything?
  (c) The duplicate check entry should be reconciled either way — confirm the
  intended polarity of `pro-bounds-pointer-arithmetic`.

## F7. R-APPC-011 — cppcheck: suppressions file unwired, syntaxError global

- **Requirement:** Run with `--error-exitcode=1 … --suppressions-list=lichen/.cppcheck-suppressions`;
  "Correctness classes (uninitvar, comparePointers, syntaxError outside known
  files) always fail the build."
- **Classification:** divergent
- **Evidence:** Both runners (`.github/workflows/ci.yml:105-121`,
  `scripts/lint-c.sh:44-56`) pass `--error-exitcode=1 --inline-suppr` but never
  `--suppressions-list`; both suppress `syntaxError` globally on the command
  line, contradicting the spec contract (the curated file confines
  `syntaxError` suppressions to 5 known files, `lichen/.cppcheck-suppressions:13-17`).
  Scan scope is subsys/lib/drivers only vs the spec command's `lichen/`.
- **Bead:** `project-LICHEN-worker6-b7z9.48`
- **Question for Opus:** Confirm the fix (wire `--suppressions-list`, drop the
  global `--suppress=syntaxError`, re-expose the 5 known files via the list),
  and decide whether `lichen/apps/` and `lichen/tests/` enter the cppcheck
  scope or the spec command is amended to subsys/lib/drivers.

## F8. R-APPC-015 — snprintf return/truncation checks: partial, heuristic evidence

- **Requirement:** "Always use these instead" (strncpy/strlcpy, snprintf) and
  "Always check return values" (snprintf truncation/error handling).
- **Classification:** divergent (low confidence)
- **Evidence:** 17 `snprintf(` call sites in lichen/subsys+lib+drivers;
  adjacent `ret < 0 | >= sizeof` style checks found at ~7 sites via a
  next-line-only heuristic — checks further away were not counted, so the
  true compliance rate is unknown. Compiler backstop: `-Wformat-truncation=2`
  is fatal under `-Werror` (not among the waived classes),
  `lichen/zephyr/CMakeLists.txt:57`.
- **Question for Opus:** Is manual verification of all 17 sites warranted, or
  is `-Wformat-truncation=2 -Werror` (plus `-Wformat-truncation` in host test
  builds) sufficient enforcement such that this row can be reclassified
  implemented (compiler-enforced)?

## F9. R-APPC-016 — Explicit-size/sizeof rules: ambiguous, no enforcement found

- **Requirement:** "Always pass explicit sizes"; "Use sizeof on arrays, not
  pointers."
- **Classification:** ambiguous
- **Evidence:** Style-level rules; no dedicated checker found. clang-tidy
  `cppcoreguidelines-*` and cppcheck cover some violations; no audit performed
  (would be a repo-wide review task, not a sweep grep).
- **Question for Opus:** Decide the enforcement story: rely on the analyzers
  (reclassify as compiler/linter-enforced, no further work), add a
  `readability-*`/`bugprone-sizeof-expression` clang-tidy check, or drop the
  row to documentation-only. No bead filed pending this decision (avoid
  manufacturing work).

## F10. R-APPC-017 — Spec's vector path points at a legacy directory

- **Requirement:** "Test vectors live in `spec/test-vectors/` as JSON" (within
  the cross-validation MUST).
- **Classification:** implemented+tested, with a doc-path divergence
- **Evidence:** The canonical, consumed location is `test/vectors/` (C tests:
  `lichen/tests/schnorr48/main.c:6,137-197`; generators in
  `lichen/tests/*/generate_vectors.py`; Python/Rust suites). `spec/test-vectors/`
  exists with 5 legacy files (frame, oscore, rpl, schc, schnorr48).
- **Question for Opus:** Should the spec text be amended to `test/vectors/`
  (AGENTS.md names that as canonical), or is `spec/test-vectors/` intended to
  remain a published snapshot that must be kept in sync? Low stakes; no bead.

## F11. Section-scope — does "all C code in LICHEN" include `firmware/`?

- **Requirement:** "This document defines mandatory safety requirements for
  all C code in LICHEN."
- **Classification:** ambiguous (scope)
- **Evidence:** The `firmware/` tree (e.g. `firmware/bridge-zephyr/`, a Zephyr
  app with its own `src/`) carries the prj.conf safety configs
  (`firmware/bridge-zephyr/prj.conf:40-43`) but its CMakeLists shows no
  hardening-flag block (no `LICHEN_HARDENING_FLAGS` equivalent), it is not in
  `lichen/west.yml`, and CI analyzers scan only `lichen/{subsys,lib,drivers}`
  (`ci.yml:113-116,130-136`). It is not a west module of the pinned workspace.
- **Question for Opus:** Is `firmware/` (a) in scope — then it needs the
  hardening flags and analyzer coverage (new bead), (b) legacy/superseded by
  `lichen/` (then mark it exempt in the spec or sunset it), or (c) a separate
  product outside the LICHEN firmware policy? This sweep did not bead it.

---

Summary: 11 flagged items (F1-F11). Beads already filed from this sweep:
`project-LICHEN-worker6-b7z9.46` (R-APPC-014), `.47` (R-APPC-010), `.48`
(R-APPC-011), `.49` (R-APPC-007/008), `.50` (R-APPC-009/013), `.51`
(R-APPC-001). F8, F9, and F11 may add beads or close rows after Opus rules;
no bead was filed for them pending those rulings.
