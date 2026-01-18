# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **acss-rs**, a Rust implementation of Asynchronous Complete Secret Sharing (ACSS) protocols for Byzantine fault-tolerant distributed systems. The codebase implements multiple protocol variants with different performance tradeoffs (linear vs quadratic communication, optimistic vs pessimistic modes).

## Build Commands

```bash
# Build all packages (release)
cargo build --release

# Build specific protocol module
cargo build --release -p dpss
cargo build --release -p g_dpss
cargo build --release -p acss_ske

# Run local tests (16 nodes)
# Usage: scripts/test.sh <protocol> <batches> <per_batch> <lin> <opt> <ibft>
scripts/test.sh dpss 1 100 true false false
```

## Running Nodes

```bash
# Run a single node
./target/release/node \
    --config testdata/hyb_16/nodes-0.json \
    --ip ip_file \
    --protocol dpss \
    --syncer testdata/hyb_16/syncer \
    --batches 1 \
    --per 100 \
    --lin true \
    --opt false \
    --ibft false

# Protocol options: dpss, g_dpss, sync
# --lin: true for linear reconstruction, false for quadratic
# --opt: true for optimistic mode, false for pessimistic
# --ibft: true to enable IBFT consensus
```

## AWS Benchmarking

```bash
cd benchmark
pip install -r requirements.txt
fab create nodes=2    # Create instances (nodes per region)
fab install           # Setup instances
fab remote            # Run benchmark
fab logs              # Download results
fab kill              # Stop running benchmark
fab destroy           # Terminate instances
```

## Architecture

### Workspace Structure

- **consensus/**: Core protocol implementations (Cargo workspace)
- **node/**: CLI binary for running protocols
- **util/**: Shared utilities (codec, I/O)
- **benchmark/**: AWS deployment scripts (Python/Fabric)
- **testdata/**: Pre-generated configs for 4/16/40 node testbeds

### Protocol Modules (in consensus/)

| Module | Description |
|--------|-------------|
| `dpss` | Dynamic Proactive Secret Sharing (primary) |
| `g_dpss` | Optimized DPSS with linear communication |
| `acss_ske` | ACSS with Symmetric Key Encryption |
| `avid` | Asynchronous Verifiable Information Dispersal |
| `acs` | Asynchronous Common Subset |
| `binary_ba` | Binary Byzantine Agreement |
| `ibft` | Istanbul Byzantine Fault Tolerance |
| `ra` | Reed-Solomon Aggregation |

### Protocol Module Pattern

Each protocol follows this structure:
```
protocol/
├── context.rs       # Main state machine and entry point
├── handlers/        # Async message handlers
├── protocol/        # Core algorithm logic
├── msg.rs           # Message type definitions
└── process.rs       # Message processing
```

### Shared Cryptographic Primitives (consensus/src/)

- `shamir/`: Threshold secret sharing
- `poly.rs`: FFT-based polynomial arithmetic (uses lambdaworks-math)
- `dzk/`: Zero-knowledge proofs
- `reed_solomon.rs`: Erasure coding
- `types.rs`: Field elements (Stark 252-bit prime), shared types

### Key External Dependencies

- `types`, `config`, `crypto`: From [Secure-Distributed-Computing-Protocols](https://github.com/akhilsb/Secure-Distributed-Computing-Protocols)
- `network`: From [libnet-rs](https://github.com/akhilsb/libnet-rs)
- `ctrbc`: Customizable Threshold RBC from reliable-broadcast-protocols
- `lambdaworks-math`: Polynomial operations, FFT
- `tokio`: Async runtime
- `rayon`: Data parallelism

### Execution Flow

1. Node starts via `main.rs`, parses CLI args and loads config
2. Network layer initializes (TcpReliableSender/TcpReceiver)
3. Protocol context spawns, sets up cryptographic state
4. Main loop processes messages through handlers
5. Protocol executes ACSS phases: share generation, verification, reconstruction
6. Results logged, syncer coordinates termination

### Configuration

- Node configs: JSON files in `testdata/hyb_*/nodes-*.json`
- Syncer endpoints: `testdata/hyb_*/syncer`
- IP overrides: `ip_file` (localhost ports for local testing)
- Benchmark settings: `benchmark/settings.json`
