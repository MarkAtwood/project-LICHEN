=== BLE Ingress + MeshCore BLE Validation Artifacts for bead project-LICHEN-2auf.59.4.1.3.2.1.2 ===
Generated: Thu Jul 23 23:33:27 UTC 2026
Clean worktree: /mnt/lichen-zephyr/work/project-LICHEN-2auf-59-mcble-213-head
Board: native_sim/native/64 (Zephyr 3.7)

## Test Results

### ble_ingress (4/4 passed)
- test_ble_lci_iface_is_configured_for_slip_link: PASS
- test_injects_ipv6_to_rx_path: PASS
- test_rejects_malformed_ipv6: PASS
- test_reply_exits_ble_lci_egress_path: PASS

### meshcore_ble (10/10 passed)
- test_init_uses_meshcore_owner_advertising: PASS
- test_owner_connection_write_and_disconnect_cleanup: PASS
- test_reconnect_rejects_old_connection_write: PASS
- test_reset_session_if_epoch_preserves_new_session: PASS
- test_rx_queue_backpressure: PASS
- test_rx_rejects_serial_prefixes_and_oversize: PASS
- test_rx_write_dequeues_raw_frame_with_epoch: PASS
- test_stale_connection_write_is_rejected: PASS
- test_tx_rejects_serial_prefix_and_backpressure: PASS
- test_tx_requires_active_session_and_preserves_epoch: PASS

## Build Details
- BLE ingress: west build -b native_sim/native/64 lichen/tests/ble_ingress -d build/ble-ingress-worktree -- -DZEPHYR_EXTRA_MODULES=$PWD/lichen
- MeshCore BLE: west build -b native_sim/native/64 lichen/tests/meshcore_ble -d build/meshcore-ble-worktree -- -DZEPHYR_EXTRA_MODULES=$PWD/lichen

## SHA256 of Build Artifacts
435cc79bf5523fff4ec1d10098b7b9286b05c75e8fa7fd0828b0268a75424788  build/ble-ingress-worktree/zephyr/zephyr.elf
73475a4bf553da80be704a4f3cec65798089115f19d96d01dfd9892da21a5102  build/ble-ingress-worktree/zephyr/zephyr.exe
954028594a5da2338fa4c3b3131a4fce993becb925832c453935c1d713da0a57  build/ble-ingress-worktree/CMakeCache.txt
b1e8c3dafa137ddfedf0b4344030b712cd0e33877739fc823d3227b80cdc6150  build/ble-ingress-worktree/zephyr_modules.txt
66e3d737435bee90a0dda3f39559459b32d9bff988f00c8716b4e7c4036a0cde  build/meshcore-ble-worktree/zephyr/zephyr.elf
f4c9e558f10595ce9e1526ebb237270f8b085a60cd2c1f22a18e24fbe0cce24b  build/meshcore-ble-worktree/zephyr/zephyr.exe
7765398c0a8b8aee32b1b0ec638829868a66609d7299c537dccf9572ea02ecc8  build/meshcore-ble-worktree/CMakeCache.txt
9f5eccdf82bf0cb35e42a92495ee749951773c4ae03d124b4b19815d2f9fab4c  build/meshcore-ble-worktree/zephyr_modules.txt
