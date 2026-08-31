# Local dependency patches

## Zephyr / west modules

The `zephyr/` west module is pinned to upstream **v3.7.0** plus the local
changes captured in `zephyr-v3.7.0-local.patch`, and `modules/lib/loramac-node`
carries `loramac-node-local.patch`. `west update` will discard both — re-apply
with:

```bash
cd zephyr && git apply ../patches/zephyr-v3.7.0-local.patch && cd ..
cd modules/lib/loramac-node && git apply ../../../patches/loramac-node-local.patch
```

Zephyr contents (one combined diff, five files):

| File | What / why |
|---|---|
| `drivers/lora/sx126x.c` | `SX126xWaitOnBusy()`: 500 ms deadline + hard radio reset instead of waiting forever on a stuck BUSY line (radio lockup resilience). |
| `drivers/usb/device/usb_dc_nrfx.c` | Old-stack USB fixes for boards whose bootloader leaves USB active (ghost power events, T1000-E bring-up era). |
| `drivers/usb/udc/udc_nrf.c` | NEXT-stack: defer D+ pull-up when the READY power event fires before `udc_nrf_enable()` (ghost event from a USB-active bootloader); assert pull-up unconditionally in enable. |
| `subsys/usb/device_next/class/usbd_cdc_acm.c` | **Priority-inversion livelock fix.** The CDC-ACM workqueue runs at cooperative priority; handlers that couldn't make progress (CDC_ACM_LOCK held by a preemptible thread in `poll_out`/`poll_in`, buf pool empty, or IRQ-pending retry) resubmitted themselves immediately, monopolizing the CPU so the lock holder never ran again — on the T-Echo this starved the WDT heartbeat and hard-reset the SoC ~4 s after *any* host port open (bd `lora_ipv6_mesh-ihm3`). Retry paths now back off one tick via `k_work_delayable`; fresh-event paths are unchanged (`K_NO_WAIT`). Candidate for upstreaming — check whether Zephyr ≥3.8 already restructured this driver before submitting. |
| `drivers/lora/sx12xx_common.c` | **RX window preamble-hold.** `lora_recv()`'s host-side timeout aborted receptions already in progress; with 1 s application windows a ~0.7 s SF10 frame rarely survived the boundary. The recv path now records radio RX activity (via the `RadioRxActivity()` hook patched into loramac-node) and holds the window open — bounded by one max-frame airtime — while a frame is arriving. Raised the bench CoAP first-attempt rate from ~69% to ~93% at 1 s windows (bd `lora_ipv6_mesh-c3wn`). |

loramac-node contents (`loramac-node-local.patch`):

| File | What / why |
|---|---|
| `src/radio/sx126x/radio.c` | Adds a weak no-op `RadioRxActivity()` hook, called from `RadioIrqProcess()` on PREAMBLE_DETECTED / SYNCWORD_VALID / HEADER_VALID (previously ignored). Platforms override it to implement receive-window holding; unpatched consumers are unaffected. |

# Local Rust crate patches

**Status since 2026-08-30:** `oscore` is **vendored in-tree** at
`rust/crates/oscore` (commit `61540bccff`) — the `rust/Cargo.toml`
`[patch.crates-io]` entry points there, and nothing applies
`rust-oscore-local.patch` anymore. The vendored crate carries upstream v0.1.2
content (its manifest version field is still 0.1.0; the vendoring commit did
not bump it). It ships:

- `Context::begin_unprotect_observe_response` — observe-notification unprotect
  (RFC 8613 §4.2). Notifications share the registration request's PIV, so the
  one-response-per-request guard must not apply; a fresh explicit PIV is
  mandatory because a request-derived nonce would alias across notifications;
  the notification PIV replay window is enforced.
- `Context::master_secret` — read-only accessor for gateway trust tests.

Replay-window semantics are pinned by the crate unit tests
`observe_replay_window_accepts_out_of_order_once_and_rejects_old` and its
ordinary-path twin `ordinary_replay_window_accepts_out_of_order_once_and_rejects_old`,
run standalone from `rust/crates/oscore` (the vendored manifest carries an
empty `[workspace]` table so in-place `cargo test` works). The observe flow is
additionally pinned by the workspace test
`protected_observe_registration_notifications_retries_blocks_and_reset`.

`rust-oscore-local.patch` is retained **as a historical record only** of the
interim port that lived in the machine-local clone (upstream `main` at
`7434512` + port, superseded by v0.1.2's dedicated `received_response_piv`
window design). Do **not** apply it. Removing the file entirely is pending a
maintainer decision (bd `project-LICHEN-worker6-s549`); the same bead tracks
deleting the uncompiled dead modules (`src/context.rs`, `src/protect.rs`,
`src/unprotect.rs`, `src/option.rs`, `src/crypto.rs`, `src/group.rs`,
`src/types.rs`, `src/tests.rs`) from the vendored/external crate source.
Upstream pushes of the crate need Mark's explicit authorization.
