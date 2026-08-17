# CYBERPHY

Python-based network scanning and packet capture project developed for practical network security validation, traffic analysis, and basic security assessment.

## Overview

CYBERPHY is a security-focused Python project designed to perform core network analysis tasks, including host discovery, port scanning, packet capture, and PCAP export. It was developed as part of the final project for the Tokio School Cybersecurity course and demonstrates practical use of Python in network security workflows.

The project supports controlled security testing and network visibility by combining scanning and traffic capture capabilities in a single tool. ISO/IEC 27002 was used as a reference framework for structuring security-related observations.

## Features

- Host discovery across one or multiple IP addresses
- Port scanning for target systems and defined port ranges
- IP address validation before execution
- Network interface detection and selection
- Packet capture for traffic inspection and troubleshooting
- Export of captured traffic to `.pcap` files for later analysis
- Support for organizing security findings using ISO/IEC 27002 as a reference

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

## Workflow

1. Enter one or more IP addresses.
2. Define the port range to scan.
3. Select the network interface to use.
4. Run host and port scanning.
5. Capture network traffic for a defined period.
6. Export captured packets to a `.pcap` file if required.

## Project Value

This project demonstrates practical skills in:

- Python scripting for security tasks
- Network enumeration and service discovery
- Packet capture and traffic inspection
- Basic security validation in controlled environments
- Structuring findings with reference to security standards

## CV Summary

**CYBERPHY** - Python-based network scanning and packet capture project.  
Developed a tool for host discovery, port scanning, packet capture, and PCAP export using Python, Nmap, and Scapy. Analyzed captured traffic and organized security findings using ISO/IEC 27002 as a reference.
