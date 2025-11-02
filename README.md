# TLS vs QUIC Performance Benchmark

This repository contains scripts and Docker configurations to automate performance benchmarks comparing TLS (over TCP) and QUIC (UDP) using quantum-safe signature and KEM algorithms.

## Project Overview

This project automates performance testing of TLS vs QUIC with various quantum-safe signature (SIG) and key encapsulation (KEM) algorithms. It uses Docker containers for:

1. Generating certificates with selected SIG algorithms  
2. Running server and client workloads under the `oqs` Docker image  
3. Optionally applying network impairments (delay, loss) via Pumba  
4. Capturing network traffic using Wireshark  
5. Cleaning up Docker resources after each test

## Prerequisites

- **Docker** installed and running  
- **Pumba** (optional) for network impairment: [github.com/alexei-led/pumba](https://github.com/alexei-led/pumba)  
- **Wireshark** installed and accessible (`wireshark` on Linux or `/Applications/Wireshark.app` on macOS)  
- `oqs` Docker image built with the test scripts (`doCert.sh`, `perftestServerTlsQuic.sh`, `perftestClientTlsQuic.sh`)  

## Contains

- **`Launcherv3.sh`** — Main benchmarking script  
- **`Docker/`** — Dockerfiles  
- **`Ideal/`** — Ideal case  
- **`Size/`** — Size evaluation of the ideal case  
- **`Delays/`** — Delays evaluation  
- **`Loss/`** — Loss evaluation  
- **`README.md`** — This file 

   
## Installation

1. **Build the Docker image**:
   ```bash
   docker build -t oqs .
   ```
2. **Make the launcher executable**:
   ```bash
   chmod +x Launcherv3.sh
   ```

## Usage

```bash
./Launcherv3.sh <protocol> <auth-mode> <capture-mode> <network-profile> <loss-percent> <delay-ms>
```

| Parameter          | Description                                                          | Values                                 | Default |
|--------------------|----------------------------------------------------------------------|----------------------------------------|---------|
| `<protocol>`       | Transport protocol                                                   | `tls`, `quic`                          | `tls`   |
| `<auth-mode>`      | Authentication mode                                                  | `single` (server-only), `mutual`       | `single`|
| `<capture-mode>`   | Packet capture options                                               | `capture`, `captureKey`, `nocapture`   | `nocapture`|
| `<network-profile>`| Network impairment profile                                           | `none`, `simple`, `stable`, `unstable`| `none`  |
| `<loss-percent>`   | Packet loss percentage (only for `simple`)                           | Integer 0–100                          | `0`     |
| `<delay-ms>`       | Delay in milliseconds (only for `simple`)                            | Integer ≥ 0                            | `0`     |

### Network Profiles

- `none`: No delay or loss.  
- `simple`: Static impairment — specify `<loss-percent>` and `<delay-ms>`.  
- `stable`: Stable GE-model loss (pg10 pb50 h70 k10).  
- `unstable`: Unstable GE-model loss (pg20 pb40 h90 k20).

### Examples

```bash
# 1) TLS, server-only auth, key capture, no impairments
./Launcherv3.sh tls single captureKey none 0 0

# 2) QUIC, server-only auth, key capture, no impairments
./Launcherv3.sh quic single captureKey none 0 0

# 3) TLS, server-only auth, no capture, no impairments
./Launcherv3.sh tls single nocapture none 0 0

# 4) QUIC, mutual TLS, full capture, simple 5% loss & 50 ms delay
./Launcherv3.sh quic mutual capture simple 5 50

```
## Stadistical Evaluations

Each folder contains an Analysis folder with detailed stadistical information.

## Contributing
Contributions are welcome! Please open issues or pull requests for bug fixes, new features, or documentation improvements.
