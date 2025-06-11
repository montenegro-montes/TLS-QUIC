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


## Usage
#Launching Benchmarks
Make Launcherv3.sh executable and run:
  ./Launcher.sh [tls|quic] [mutual|single] [capture|captureKey|nocapture] [none|simple|stable|unstable] [loss-percent] [delay-ms]

## Contributing
Contributions are welcome! Please open issues or pull requests for bug fixes, new features, or documentation improvements.
