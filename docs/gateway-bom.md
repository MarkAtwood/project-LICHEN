# LICHEN Solar/LTE/Yggdrasil Gateway BOM

Target: weatherproof, solar-powered, multi-backhaul (WiFi/LTE/Ethernet), runs lichend + Yggdrasil.

## Option A: RPi-based (~$280 BOM)

| Component | Part | Price | Notes |
|-----------|------|-------|-------|
| **Compute** | Raspberry Pi Zero 2W | $15 | Quad-core, WiFi, enough for lichend |
| | microSD 32GB | $8 | Industrial grade (SanDisk Max Endurance) |
| **LoRa** | Waveshare SX1262 HAT | $25 | 868/915MHz, SPI interface |
| | LoRa antenna 868/915 | $8 | 3dBi fiberglass, N-female |
| **LTE** | Quectel BG96 USB dongle | $35 | Cat-M1/NB-IoT, low power |
| | or: SIMCom SIM7600G-H | $45 | Cat 4, faster, global bands |
| | LTE antenna (2x MIMO) | $12 | Adhesive or magnetic mount |
| | 1NCE SIM | $10 | 500MB / 10 years |
| **Power** | 20W solar panel | $30 | Monocrystalline, MC4 connectors |
| | LiFePO4 12Ah 12.8V | $50 | ~150Wh, 2000+ cycles |
| | Genasun GV-5 MPPT | $45 | 5A, waterproof potted |
| | 12V to 5V 3A DC-DC | $8 | Buck converter for Pi |
| **Enclosure** | Qilipsu 11x7x5" IP67 box | $25 | ABS, hinged lid |
| | Cable glands (PG7/PG9) | $5 | For antenna, solar, Ethernet |
| | N-bulkhead + pigtails | $10 | Panel-mount antenna feed |
| **Ethernet (optional)** | USB-Ethernet adapter | $10 | For Starlink/wired backhaul |
| **Total** | | **~$280** | Without Ethernet option |

## Option B: CM4-based (~$380 BOM)

Swaps RPi Zero 2W for Compute Module 4 + carrier. More I/O, native Ethernet, M.2 for LTE.

| Component | Part | Price | Notes |
|-----------|------|-------|-------|
| **Compute** | RPi CM4 (2GB, WiFi) | $45 | |
| | Waveshare CM4-IO-BASE-A | $25 | M.2 slot, Ethernet, USB |
| | microSD 32GB | $8 | |
| **LoRa** | Waveshare SX1262 HAT | $25 | |
| | LoRa antenna | $8 | |
| **LTE** | Quectel RM502Q-AE M.2 | $80 | 5G/LTE Cat 20, overkill but future-proof |
| | or: Quectel EC25 M.2 | $40 | LTE Cat 4, plenty |
| | LTE antennas | $12 | |
| | 1NCE SIM | $10 | |
| **Power** | Same as Option A | $133 | |
| **Enclosure** | Same as Option A | $40 | |
| **Total** | | **~$380** | With EC25 |

## Option C: Custom PCB (~$60 BOM at 100+)

For 500-unit deployment, custom board saves cost and integration headaches.

| Component | Est. cost @100 | Notes |
|-----------|----------------|-------|
| nRF52840 + SX1262 | $12 | Single module (RAK4630 or custom) |
| W5500 Ethernet PHY | $3 | SPI Ethernet, for Starlink |
| Quectel BG96 | $15 | LTE Cat-M1 |
| ESP32-C3 (optional) | $3 | WiFi coprocessor |
| MPPT + LiFePO4 charger | $8 | Integrated TI BQ25895 or similar |
| LiFePO4 cell 6Ah | $15 | 3.2V, series for 12.8V or single + boost |
| PCB + assembly | $5 | JLCPCB/PCBWAY |
| **Total** | **~$60** | Plus enclosure, antennas, solar |

Custom board runs Zephyr (not Linux), so lichend would need porting or run native C gateway.

---

## Power budget

| Load | Current @5V | Duty | Avg |
|------|-------------|------|-----|
| RPi Zero 2W idle | 100mA | 100% | 100mA |
| RPi processing | 300mA | 10% | 30mA |
| SX1262 RX | 10mA | 90% | 9mA |
| SX1262 TX | 120mA | 1% | 1.2mA |
| BG96 idle | 10mA | 100% | 10mA |
| BG96 TX | 500mA | 1% | 5mA |
| **Total avg** | | | **~160mA** |

At 5V, ~0.8W average. 150Wh battery = 8 days without sun. 20W panel in partial sun (4 peak hours) = 80Wh/day, plenty of margin.

---

## Software stack

```
┌─────────────────────────────────────┐
│           lichend (Rust)            │
├─────────────────────────────────────┤
│  Yggdrasil ←→ tun0 (02::/7)         │
├──────────┬──────────┬───────────────┤
│  wwan0   │   eth0   │    wlan0      │
│  (LTE)   │(Starlink)│   (WiFi)      │
└──────────┴──────────┴───────────────┘
         ↓
    1NCE / cellular
```

Yggdrasil peers over whichever backhaul is up. Failover is automatic.

---

## Sourcing

- **RPi**: Adafruit, Sparkfun, Pimoroni (check stock)
- **Quectel modems**: Aliexpress, Mouser, or Sixfab (pre-integrated HATs)
- **Solar/battery**: Amazon, Aliexpress, or local solar supplier
- **Enclosure**: Polycase, Qilipsu (Amazon), or Fibox (industrial)
- **1NCE SIM**: 1nce.com, order online, ships globally

---

## Next steps

1. Prototype with RPi Zero 2W + Waveshare SX1262 HAT + BG96 USB (Option A)
2. Validate power budget with real solar/battery
3. If 500-unit deployment confirmed, design custom PCB (Option C)
