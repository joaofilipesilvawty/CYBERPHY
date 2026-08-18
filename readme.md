# CYBERPHY

Python-based network scanning and packet capture project developed for practical network security validation, traffic analysis, and basic security assessment.

## Overview

CYBERPHY is a security-focused Python project designed to perform core network analysis tasks, including host discovery, port scanning, packet capture, and PCAP export. It was developed as part of the final project for the Tokio School Cybersecurity course and demonstrates practical use of Python in network security workflows.

The project now runs as an interactive command-line application (`server.py`) with a menu-driven interface for running scans, capturing traffic, and reviewing past scan history stored in `scan_history.json`.

## Features

- Interactive terminal menu driven by `server.py`
- Host discovery across one or multiple IP addresses (supports CIDR notation)
- Port scanning for target systems and defined port ranges
- IP address and CIDR network validation before execution
- Network interface detection and selection
- Packet capture for traffic inspection and troubleshooting
- Full scan combining host discovery, port scanning, and packet capture
- Scan history persisted to `scan_history.json`
- Export of captured traffic to `.pcap` files for later analysis
- Sudo auto-restart for Nmap privileges

## Use Cases

CYBERPHY can be used in controlled lab or educational environments for:

- Identifying active hosts on a network
- Reviewing exposed services and open ports
- Capturing traffic for troubleshooting and behavioral analysis
- Saving PCAP files for review in tools such as Wireshark
- Supporting basic security validation activities

## Technologies Used

- **Python**
- **Nmap**
- **Scapy**
- **Psutil**
- **Socket**
- **Logging**
- **Concurrent Futures**

## Setup

1. Clone the repository.
2. Run `./start.sh` from the project root.

On the first run, `start.sh` creates a Python virtual environment in `.env` and installs the dependencies from `requirements.txt`.

## Usage

After launching the application with `./start.sh`, the CYBERPHY menu is displayed:

1. **Descoberta de Hosts** — Discover active hosts on a target IP or CIDR range.
2. **Escaneamento de Portas** — Scan ports on a target with customizable Nmap options.
3. **Captura de Pacotes** — Capture packets on a selected network interface.
4. **Scan Completo** — Run host discovery, port scanning, and packet capture in sequence.
5. **Ver Interfaces de Rede** — List available network interfaces.
6. **Histórico de Scans** — Review previous scans saved in `scan_history.json`.
0. **Sair** — Exit the application.

## Workflow

1. Launch the application with `./start.sh`.
2. Choose an option from the menu.
3. Enter the target IP(s) or CIDR range when prompted.
4. Define the port range and Nmap options for scans.
5. Select the network interface to use for packet capture.
6. Review the results and optionally save captured packets to a `.pcap` file.

## Project Value

This project demonstrates practical skills in:

- Python scripting for security tasks
- Network enumeration and service discovery
- Packet capture and traffic inspection
- Basic security validation in controlled environments
- Structuring findings with reference to security standards

## CV Summary

**CYBERPHY** — Python-based network scanning and packet capture project.
Developed a tool for host discovery, port scanning, packet capture, and PCAP export using Python, Nmap, and Scapy. Analyzed captured traffic and organized security findings using ISO/IEC 27002 as a reference.
