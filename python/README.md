<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Python Prototype

Python implementation of the LICHEN mesh networking stack for protocol validation and simulation.

This prototype validates the protocol design before committing to embedded implementations. It includes a full network simulator with realistic radio propagation, multi-node topologies, and comprehensive test coverage for all routing algorithms.

## Setup

```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Module Structure

```
src/lichen/
├── sim/        # Network simulator (radio medium, propagation, chaos testing)
├── tui/        # Interactive terminal UI for simulated nodes
├── radio/      # Radio abstraction (real hardware + simulator client)
├── link/       # Link layer (frames, Schnorr signatures, replay protection)
├── schc/       # SCHC compression/decompression (RFC 8724)
├── ipv6/       # IPv6 packet handling (addresses, headers, ICMPv6)
├── routing/    # Unified routing table and gradient management
├── announce/   # Announce routing (peer-to-peer gradient protocol)
├── rpl/        # RPL routing (border router tree protocol)
├── loadng/     # LOADng routing (reactive route discovery)
├── coap/       # CoAP resources and OSCORE integration
└── crypto/     # Schnorr signatures, key management
```

## Running the Simulator

The simulator provides a controlled environment for testing LICHEN nodes without real hardware.

```bash
# Start the simulator server
lichen-sim --node-port 4444 --api-port 4445
```

### Simulator Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Simulation Server                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Simulation Space                        │    │
│  │   ┌──────┐  ┌──────┐  ┌──────┐                      │    │
│  │   │Node A│  │Node B│  │Node C│  ...                 │    │
│  │   └──┬───┘  └──┬───┘  └──┬───┘                      │    │
│  │      │         │         │                          │    │
│  │      └─────────┴─────────┘                          │    │
│  │              Radio Medium                            │    │
│  │         (propagation model, collisions)             │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│    ┌─────────────────────┼─────────────────────┐            │
│    │                     │                     │            │
│  ┌─┴──┐              ┌───┴───┐            ┌────┴────┐       │
│  │TCP │              │ REST  │            │WebSocket│       │
│  │4444│              │ 4445  │            │4445/ws  │       │
│  └─┬──┘              └───┬───┘            └────┬────┘       │
└────┼─────────────────────┼─────────────────────┼────────────┘
     │                     │                     │
┌────┴────┐          ┌─────┴─────┐         ┌─────┴─────┐
│SimRadio │          │ curl/httpx│         │  TUI App  │
│ client  │          │  scripts  │         │           │
└─────────┘          └───────────┘         └───────────┘
```

**Ports:**
- **TCP 4444** — SimRadio node connections (binary protocol)
- **REST 4445** — Simulation management API
- **WebSocket 4445/ws** — Real-time event streaming

### REST API

Create and manage simulations via HTTP:

```bash
# Create a simulation
curl -X POST http://localhost:4445/simulations \
  -H "Content-Type: application/json" \
  -d '{"id": "test1"}'

# Add nodes
curl -X POST http://localhost:4445/simulations/test1/nodes \
  -H "Content-Type: application/json" \
  -d '{"id": "alice", "x": 0, "y": 0, "z": 0}'

curl -X POST http://localhost:4445/simulations/test1/nodes \
  -H "Content-Type: application/json" \
  -d '{"id": "bob", "x": 100, "y": 0, "z": 0}'

# Advance simulation time (1 second = 1,000,000 microseconds)
curl -X POST http://localhost:4445/simulations/test1/tick \
  -H "Content-Type: application/json" \
  -d '{"time_us": 1000000}'

# Get simulation state
curl http://localhost:4445/simulations/test1

# Get topology graph
curl http://localhost:4445/simulations/test1/topology

# Get metrics
curl http://localhost:4445/simulations/test1/metrics

# Delete simulation
curl -X DELETE http://localhost:4445/simulations/test1
```

### Chaos Testing

Inject network faults to test resilience:

```bash
# Drop all packets from a node
curl -X POST http://localhost:4445/simulations/test1/chaos/drop \
  -H "Content-Type: application/json" \
  -d '{"node_id": "alice", "direction": "tx"}'

# Partition the network into groups
curl -X POST http://localhost:4445/simulations/test1/chaos/partition \
  -H "Content-Type: application/json" \
  -d '{"groups": [["alice", "bob"], ["charlie", "dave"]]}'

# Degrade signal quality
curl -X POST http://localhost:4445/simulations/test1/chaos/degrade \
  -H "Content-Type: application/json" \
  -d '{"node_id": "alice", "snr_penalty_db": 10}'

# Add a jammer
curl -X POST http://localhost:4445/simulations/test1/chaos/jammer \
  -H "Content-Type: application/json" \
  -d '{"x": 50, "y": 50, "z": 0, "radius_m": 100}'

# Clear all chaos rules
curl -X DELETE http://localhost:4445/simulations/test1/chaos
```

### WebSocket Events

Connect to `/simulations/{id}/ws` for real-time events:

```javascript
const ws = new WebSocket('ws://localhost:4445/simulations/test1/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.event, data);
};

// Events: tx_start, tx_end, rx_success, rx_timeout, collision, node_added, node_removed

// Subscribe to specific events only
ws.send(JSON.stringify({cmd: 'subscribe', events: ['tx_start', 'collision']}));
```

## Interactive TUI Node

Launch an interactive terminal node that connects to a running simulation:

```bash
# Start the simulator
lichen-sim --node-port 4444 --api-port 4445

# In another terminal, launch the TUI
lichen-tui --host localhost --port 4444 --sim default --node mynode --position 0,0,0
```

**Keyboard shortcuts:**
| Key | Action |
|-----|--------|
| `c` | Connect to simulator |
| `t` | Focus transmit input |
| `r` | Start receive |
| `d` | Disconnect |
| `q` | Quit |

**Transmit:** Enter hex (`48656c6c6f`) or text (`hello`) and press Enter.

**Receive:** Set timeout in milliseconds and click Start Receive. Received packets show payload, RSSI, and SNR.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=lichen

# Run specific test categories
pytest tests/sim/           # Simulator tests
pytest tests/link/          # Link layer tests
pytest tests/routing/       # Routing tests
pytest tests/schc/          # SCHC compression tests

# Run with verbose output
pytest -v

# Stop on first failure
pytest -x
```

### Test Categories

| Directory | Coverage |
|-----------|----------|
| `tests/sim/` | Simulator, propagation, chaos, multi-node scenarios |
| `tests/link/` | Frame encoding, signatures, replay protection |
| `tests/routing/` | Gradient table, announce, RPL, LOADng |
| `tests/schc/` | Header compression, fragmentation, reassembly |
| `tests/ipv6/` | Address handling, packet encoding |
| `tests/coap/` | CoAP resources, OSCORE |

## Writing SimRadio Clients

Connect custom code to the simulator using the SimRadio client:

```python
import anyio
from lichen.radio.sim_client import SimRadio

async def main():
    async with SimRadio(
        host="localhost",
        port=4444,
        sim_id="default",
        node_id="mynode",
        position=(0.0, 0.0, 0.0),
    ) as radio:
        # Transmit a packet
        success = await radio.transmit(b"Hello, mesh!")
        print(f"TX {'succeeded' if success else 'failed'}")

        # Receive with timeout
        result = await radio.receive(timeout_ms=5000)
        if result:
            payload, rssi, snr = result
            print(f"RX: {payload} (RSSI={rssi}dBm, SNR={snr}dB)")
        else:
            print("RX timeout")

        # Get simulation time
        time_us = await radio.get_time()
        print(f"Sim time: {time_us}us")

anyio.run(main)
```

## License

Copyright by the contributors to the LICHEN project.

GPL-3.0-or-later
