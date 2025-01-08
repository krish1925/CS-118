# README

## CS 118: Computer Network Fundamentals - Fall 2024

This repository contains the three programming projects for **CS 118: Computer Network Fundamentals**. The course introduces fundamental concepts in designing and implementing computer communication networks, their protocols, and applications. Topics covered include:

- Layered network architecture
- Physical layer and data link protocols
- Network and transport protocols
- Unicast and multicast routing protocols
- Applications with examples from the Internet TCP/IP protocol suite

The course includes two programming projects to give students hands-on experience in network programming and the development of simple network applications.

---

## Repository Overview

### Project 0: Non-Blocking Sockets
In this introductory project, students develop a basic socket implementation with non-blocking functionality, enabling efficient communication without blocking program execution. Key features include:
- Basic socket setup
- Non-blocking communication
- Asynchronous message handling

### Project 1: Reliable UDP Client-Server Implementation
This project focuses on implementing a reliable data transfer mechanism over UDP, which is inherently unreliable. The main components are:
- **Packet Structure:** Includes sequence numbers, acknowledgment numbers, and flags (SYN/ACK).
- **Connection Management:** Implements a three-way handshake similar to TCP.
- **Windowing and Retransmission:** Uses a sliding window of 20 packets and handles retransmissions.
- **Non-Blocking Sockets:** Integrates asynchronous communication from Project 0.
- **Diagnostic Logging:** Tracks packet flow for debugging.

#### Challenges Addressed:
- Handling packet loss with retransmission
- Ensuring in-order delivery using sequence numbers
- Synchronizing client-server states for reliable communication

### Project 2: Secure UDP Communication
Building on Project 1, this project introduces a security layer using OpenSSL's libcrypto. It ensures:
- **Identity Verification:** Authentication of clients and servers.
- **Privacy:** Encrypting communication for confidentiality.
- **Data Integrity:** Protecting against tampering using HMAC.

#### Key Features:
- **State Machine:** Manages handshake phases and secure data transmission.
- **TLV Encoding:** Structures messages using Type-Length-Value for flexible parsing.
- **OpenSSL Integration:** Handles cryptographic operations for key exchange, encryption, and verification.

#### Challenges Addressed:
- Integrating OpenSSL APIs for cryptographic operations
- Debugging HMAC verification and TLV parsing
- Maintaining synchronized states between client and server

---

## Conclusion
These projects provide a comprehensive introduction to network programming, from establishing basic communication to building secure and reliable client-server systems. The course and these projects emphasize practical skills in network architecture, protocol design, and real-world communication scenarios.
