# NUCLEO-WL55JC Renode Simulation

Run STM32WL55 Zephyr firmware in Renode with lichen-sim radio simulation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Renode                                                       │
│  ┌──────────────────┐    ┌──────────────────────────────┐   │
│  │ Zephyr Firmware  │    │ LichenSubGHz.cs              │   │
│  │ (lora_renode.c)  │───▶│ Memory-mapped at 0x58010000  │   │
│  └──────────────────┘    └───────────────┬──────────────┘   │
└────────────────────────────────────────────┼────────────────┘
                                             │ TCP socket
                                             ▼
                              ┌──────────────────────────────┐
                              │ lichen-sim (Python)          │
                              │ RenodeServer on port 5555    │
                              └──────────────────────────────┘
```

## Quick Start

1. Start lichen-sim with Renode server:
   ```python
   from lichen.sim.simulation import Simulation
   from lichen.sim.renode_server import start_renode_server
   import asyncio

   async def main():
       sim = Simulation("test")
       server, port = await start_renode_server(sim, "renode-node", port=5555)
       # ... keep running
   ```

2. Build firmware with Renode overlay:
   ```bash
   west build -b nucleo_wl55jc lichen/samples/lora_ping -- \
     -DDTC_OVERLAY_FILE=lichen/boards/renode/nucleo_wl55jc/nucleo_wl55jc_renode.overlay \
     -DEXTRA_CONF_FILE=lichen/boards/renode/nucleo_wl55jc/renode.conf
   ```

3. Run in Renode:
   ```bash
   renode --disable-gui -e \
     'set elf @build/zephyr/zephyr.elf; include @lichen/boards/renode/nucleo_wl55jc/support/nucleo_wl55jc.resc; start'
   ```

## Files

- `peripherals/LichenSubGHz.cs` - C# Renode peripheral (TCP client)
- `support/stm32wl55.repl` - Platform description
- `support/nucleo_wl55jc.resc` - Renode script
- `nucleo_wl55jc_renode.overlay` - DTS overlay for simulator driver
- `renode.conf` - Kconfig fragment

## Memory Map (LichenSubGHz)

| Offset | Name        | Access | Description                    |
|--------|-------------|--------|--------------------------------|
| 0x000  | TX_LEN      | W      | Payload length to send         |
| 0x004  | TX_TRIGGER  | W      | Trigger transmission           |
| 0x008  | TX_STATUS   | R      | 0=idle, 1=busy, 2=done, 3=fail |
| 0x00C  | TX_AIRTIME  | R      | Last TX airtime (us)           |
| 0x010  | RX_STATUS   | R      | 0=empty, 1=packet available    |
| 0x014  | RX_LEN      | R      | Received payload length        |
| 0x018  | RX_RSSI     | R      | RSSI (int16, dBm)              |
| 0x01C  | RX_SNR      | R      | SNR * 10 (int16)               |
| 0x020  | RX_CONSUME  | W      | Consume RX packet              |
| 0x024  | CONNECT     | W      | Connect to lichen-sim          |
| 0x100  | TX_BUFFER   | R/W    | 256-byte TX payload buffer     |
| 0x200  | RX_BUFFER   | R      | 256-byte RX payload buffer     |
