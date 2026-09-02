## spec/appendix-c-safety.md — coverage (sweep 2026-08-31)

17 requirements extracted (prefix `R-APPC`, following the `R-ABR`/`R-ABF`
precedent). This appendix is a build/CI policy section, not a wire-protocol
section: "test evidence" means a wired CI gate or harness, not a unit test;
several rows are configuration or process requirements. Not extracted as
requirements: the flag-purpose tables, ASan/UBSan catch-lists, Coverity setup
instructions, the fuzz-harness example, the hardware-status table (informative),
and the CERT rule summary tables (enforced via the analyzers — cited in the
R-APPC-010/011 rows). The `-fbounds-safety`/`safe-stack`/MTE/CHERI/CET items
and the "Future: Hardware Memory Safety" table are keyword-less or lowercase-
should and explicitly conditional/future — noted, never beaded. Gap beads filed
under epic `project-LICHEN-worker6-b7z9`, labels `c-safety` + `spec-gap`
(+`zephyr`/`ci` where apt): **6** (cap 10; overflow 0). R-APPC-009 and
R-APPC-013 share bead `project-LICHEN-worker6-b7z9.50` (one fix site:
fuzz testcase.yaml + sanitizers.conf wiring). Adjacent hygiene observation (not
a spec requirement, not beaded here): build debris is committed under
`lichen/tests/fuzz/build/` (incl. `a.out`) and stray `*.o` files sit next to
the fuzz sources.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-APPC-001 | All C code MUST be compiled with these flags (Basic Flags block: -Wall -Wextra -Werror, -Wformat=2 -Wformat-security -Wformat-truncation=2, -Wshadow, -Wconversion -Wno-sign-conversion, -Wdouble-promotion, -Wnull-dereference, -Wcast-align, -Wlogical-op -Wduplicated-cond -Wduplicated-branches, -Warray-bounds=2, -Wstack-usage=2048, -Wswitch-enum, -Wstrict-aliasing=2 -fstrict-aliasing, -Wmaybe-uninitialized, -fstack-protector-strong) | divergent | Full set implemented: `LICHEN_HARDENING_FLAGS` lichen/zephyr/CMakeLists.txt:48-135, applied to every lichen module library target (:169-185); host tests via lichen/tests/cmake/test_common.cmake:56-63. Documented deviations: -Wno-error=conversion :71, -Wno-error=cast-align :78, -Wno-error=duplicated-branches :110, -Wno-error=cpp :125; -fstack-protector-strong deliberately not raw — routed via CONFIG_STACK_CANARIES (:115-118; Zephyr emits -fstack-protector-all), literal flag in test_common.cmake:63; per-file exemptions: vendored lr1110 (drivers/lora/lr1110/CMakeLists.txt:22), monocypher -Wno-error=stack-usage (subsys/lichen/crypto/CMakeLists.txt:13-19). Spec preamble: "NO EXCEPTIONS. NO WAIVERS." — bead `project-LICHEN-worker6-b7z9.51` | high |
| R-APPC-002 | When toolchain supports it, enable advanced protections: CFI + hidden visibility (Clang 18+), -fbounds-safety, -fsanitize=safe-stack (keyword-less conditional imperative) | implemented+untested (CFI only) | CFI: lichen/zephyr/CMakeLists.txt:141-154 enables -fsanitize=cfi -fvisibility=hidden when Clang >= 18 (dormant under GCC-based Zephyr SDK 0.16.8; no test can exercise it today). -fbounds-safety / -fsanitize=safe-stack: zero hits repo-wide — precondition (Clang 18+ toolchain in use) unmet, conformant absence | high |
| R-APPC-003 | All new code MUST use bounds annotations where applicable (__counted_by, _Nonnull/_Nullable, nonnull attr, pass_object_size) | implemented+untested | Annotations present in 15+ files: lichen/subsys/lichen/hal/include/lichen/hal.h (23 matches), gcp/include/lichen/gcp_trust.h (25), oscore/include/lichen/edhoc.h (33), schc/include/lichen/schc.h (9), link/include/lichen/tx_queue.h (18), oscore/oscore_ctx.c (19). No CI mechanism verifies "all new code" — flagged (low) | low |
| R-APPC-004 | Hardware memory safety (MTE/CHERI/CET) "should be enabled when LICHEN runs on Linux/application processors"; spec itself: "not yet applicable to Cortex-M" | not-implemented (conformant — explicitly future, lowercase should) | Zero hits for -fsanitize=memtag / -fcf-protection repo-wide | high |
| R-APPC-005 | All firmware builds MUST enable in prj.conf: CONFIG_STACK_CANARIES=y, CONFIG_STACK_SENTINEL=y | implemented+untested | lichen/apps/gateway/prj.conf:54-55, lichen/apps/puck/prj.conf:62-63, firmware/bridge-zephyr/prj.conf:40-41, lichen/tests/util/prj.conf:10-11 (20 .conf files carry CONFIG_STACK_CANARIES=y per rg) | high |
| R-APPC-006 | ...CONFIG_ASSERT=y, CONFIG_ASSERT_VERBOSE=y (disable only in release with explicit justification) | implemented+untested | Same sites: gateway prj.conf:56-57, puck:64-65, bridge-zephyr:42-43, tests/util:12-13 | high |
| R-APPC-007 | ...CONFIG_THREAD_ANALYZER=y, CONFIG_THREAD_ANALYZER_USE_PRINTK=y, CONFIG_THREAD_ANALYZER_AUTO=n (CI and debug builds) | implemented+tested | 228 conf files carry CONFIG_THREAD_ANALYZER* (all Zephyr test prj.confs + app prj.confs incl gateway/puck/bridge-zephyr); sweep's zero-hits claim was stale. Residual 3 test prj.confs (multi_root/redundant_slot/nmea_l76k) completed in b7z9.49 | high |
| R-APPC-008 | CONFIG_SYS_HEAP_VALIDATE=y (debug builds) | implemented+tested | routing_dispatch prj.conf sets it (DTN heap path); other dual-mode test prj.confs use static allocation (no SYS heap) - qualifier satisfied; b7z9.49 | high |
| R-APPC-009 | All tests run on native_sim MUST use AddressSanitizer and UndefinedBehaviorSanitizer (CONFIG_ASAN=y CONFIG_UBSAN=y, or CMake -fsanitize=address,undefined) | divergent | Standalone host CMake path compliant+tested: lichen/tests/cmake/test_common.cmake:18-19,69-86 (ASan+UBSan, -fno-sanitize-recover=all) consumed by tests/schnorr48/CMakeLists.txt:37, tests/replay/CMakeLists.txt:18, tests/tx_queue and others; CI c-standalone-tests builds them (ci.yml:137+). Zephyr native_sim path non-compliant: lichen/tests/sanitizers.conf exists (CONFIG_ASAN=y CONFIG_UBSAN=y, header cites the policy) but is referenced by nothing — no prj.conf includes it, no CI invocation passes it via EXTRA_CONF_FILE (only renode_console.conf ever is). Bead `project-LICHEN-worker6-b7z9.50` | high |
| R-APPC-010 | All C code MUST pass clang-tidy with this configuration (checks list; WarningsAsErrors '*'; CI command over lichen/subsys\|lib\|drivers) | divergent | lichen/.clang-tidy exists citing the policy (:5), WarningsAsErrors '*' (:63); config is a superset with documented suppressions beyond spec: -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling :32, -misc-redundant-expression :35, -misc-header-include-cycle :37, -bugprone-not-null-terminated-result :38, -clang-diagnostic-conversion :39, -clang-analyzer-optin.core.EnumCastOutOfRange :40; contradictory duplicate: pro-bounds-pointer-arithmetic enabled :15 vs disabled :41 (later wins). CI scope: .github/workflows/ci.yml:130-136 — `find ... \| head -50` (first 50 files, not all C code) with `-p /dev/null` (no compile DB); local scripts/lint-c.sh:63-76 covers all subsys/lib/drivers files. Bead `project-LICHEN-worker6-b7z9.47` | high |
| R-APPC-011 | cppcheck (Mandatory): --error-exitcode=1 with --suppressions-list=lichen/.cppcheck-suppressions; "Correctness classes (uninitvar, comparePointers, syntaxError outside known files) always fail the build" | divergent | Runners exist: .github/workflows/ci.yml:105-121, scripts/lint-c.sh:44-56 (--error-exitcode=1 --inline-suppr). But neither passes --suppressions-list (curated file lichen/.cppcheck-suppressions unwired), and both suppress syntaxError globally on the command line, contradicting the "syntaxError outside known files always fail" contract (file confines it to 5 known files, :13-17); scope subsys/lib/drivers only vs spec's `lichen/` (apps/tests unscanned); enable list adds portability. Bead `project-LICHEN-worker6-b7z9.48` | high |
| R-APPC-012 | Coverity Scan weekly via .github/workflows/coverity.yml (secrets COVERITY_SCAN_TOKEN/EMAIL; dashboard reviewed manually) | implemented+untested | .github/workflows/coverity.yml: weekly cron '0 0 * * 0' + workflow_dispatch; skips gracefully when secrets absent (matches the spec's once-per-fork setup steps) | high |
| R-APPC-013 | All code that parses untrusted input MUST be fuzz-tested (frame.c, schnorr48.c, schc.c) | divergent | Harnesses exist for all three named parsers: lichen/tests/fuzz/fuzz_frame.c:22 (LLVMFuzzerTestOneInput → lichen_frame_parse), fuzz_schc.c, fuzz_schnorr48.c (schnorr48_verify); CMakeLists.txt builds with -fsanitize=fuzzer or standalone+sanitizers. But no CI execution is wired: fuzz.yml:96-144 zephyr-fuzz runs `west twister -T lichen/tests/fuzz -p native_sim` nightly (schedule-only :99), yet the dir has no testcase.yaml/prj.conf → twister discovers nothing; ci.yml has no fuzz job; Rust cargo-fuzz + Python hypothesis jobs (fuzz.yml:44,153) are schedule-only with continue-on-error. Shared bead with R-APPC-009: `project-LICHEN-worker6-b7z9.50` | high |
| R-APPC-014 | Never use these functions: strcpy, strcat, sprintf, gets | divergent | Production strcpy: lichen/subsys/lichen/coap/checkin.c:1670 (`strcpy(rc->id, req.id)`), :1673 (`strcpy(rc->creator, creator)`), lichen/subsys/lichen/coap/slot_claim_settings.c:249 (constant prefix). Tests use strcpy/strcat freely (tests/checkin_rollcall/main.c:389+, tests/slot_claim_settings/main.c:179-180). No sprintf/gets in lichen/ or firmware/ (word-boundary rg clean). Bead `project-LICHEN-worker6-b7z9.46` | high |
| R-APPC-015 | Always use safe alternatives (strncpy/strlcpy, snprintf...); always check return values (snprintf truncation/error) | divergent | snprintf is the norm (17 call sites in subsys/lib/drivers); adjacent return/truncation checks found at ~7 sites (rg -A1 heuristic — some checks may be further away). Backstop: -Wformat-truncation=2 is fatal under -Werror (not waived), lichen/zephyr/CMakeLists.txt:57 | low — flagged |
| R-APPC-016 | Always pass explicit sizes; use sizeof on arrays, not pointers | ambiguous | Style-level rules with no dedicated enforcement found; clang-tidy cppcoreguidelines-* + cppcheck cover classes of it; no systematic audit performed — cannot verify compliance repo-wide. Flagged for a decision on enforcement mechanism | low |
| R-APPC-017 | All protocol logic in C MUST have equivalent tests against Python and Rust using shared test vectors ("spec/test-vectors/"; C: ZTEST_F with vector loader) | implemented+tested | C tests consume the shared vectors: lichen/tests/schnorr48/main.c:6,137-197 (vectors from test/vectors/schnorr48.json), tests/oscore_schc_roundtrip/generate_vectors.py, tests/routing_dispatch/gen_vectors.py, tests/edhoc_export/generate_fixture.py, tests/rpl_dao_sequence/main.c, tests/ping_l2/main.c, tests/coap_codec/generate_vectors.py; same JSONs feed the Python and Rust suites. Note: spec's stated path spec/test-vectors/ exists with 5 legacy files (frame, oscore, rpl, schc, schnorr48) but the canonical, consumed location is test/vectors/ — doc-path divergence, flagged (minor) | high |

### Histogram (rows)

- implemented+tested: 1 (R-APPC-017)
- implemented+untested: 5 (R-APPC-002, 003, 005, 006, 012)
- divergent: 7 (R-APPC-001, 009, 010, 011, 013, 014, 015)
- not-implemented: 3 (R-APPC-004 conformant-future, 007, 008)
- ambiguous: 1 (R-APPC-016)

### Gap beads filed (6; cap 10; overflow 0)

- `project-LICHEN-worker6-b7z9.46` (P1) — R-APPC-014: banned strcpy() in production C
- `project-LICHEN-worker6-b7z9.47` (P2) — R-APPC-010: clang-tidy CI scope + config drift
- `project-LICHEN-worker6-b7z9.48` (P2) — R-APPC-011: cppcheck suppressions file unwired, syntaxError global
- `project-LICHEN-worker6-b7z9.49` (P2) — R-APPC-007/008: THREAD_ANALYZER*/SYS_HEAP_VALIDATE absent
- `project-LICHEN-worker6-b7z9.50` (P1) — R-APPC-009/013: native_sim sanitizers + fuzz harness CI wiring orphaned
- `project-LICHEN-worker6-b7z9.51` (P2) — R-APPC-001: -Werror waivers + per-file exemptions vs "NO WAIVERS"

SHOULD-gaps: none filed (R-APPC-004 is explicitly future/conditional; R-APPC-015/016
omissions do not break a documented wire feature — noted in matrix and flagged).
MAYs: none present. No oscore/EDHOC-semantics changes are planned by any bead
here (annotations in oscore headers are cited as evidence only).

---
