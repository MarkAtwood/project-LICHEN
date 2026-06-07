# LICHEN Python Prototype

Python implementation of the LICHEN mesh networking stack for protocol validation.

## Setup

```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Structure

```
src/lichen/
├── sim/      # Wireless channel simulator
├── radio/    # Radio abstraction layer
└── link/     # Link layer (frames, signatures, replay protection)
```

## Running the Simulator

```bash
lichen-sim --node-port 4444 --api-port 4445
```

## Testing

```bash
pytest
```

## License

GPL-3.0-or-later
