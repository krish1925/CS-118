# CS118 Project 2: Security

## Description

In this project, I extended the reliable pipe from Project 1 by adding a security layer to ensure identity verification, privacy, and data integrity. The implementation uses BSD sockets with IPv4 and UDP, leveraging OpenSSL's libcrypto for cryptographic operations. The security protocol follows a handshake mechanism involving Client Hello, Server Hello, Key Exchange Request, and Finished messages, all encapsulated using Type-Length-Value (TLV) encoding.

## Design Choices

- **State Machine:** Implemented a state machine to manage the handshake phases and data transmission, ensuring proper sequencing of messages.
- **TLV Encoding:** Chose TLV for flexible and clear message structuring, allowing easy parsing and nesting of security messages.
- **OpenSSL Integration:** Utilized helper functions from `security.c/h` to abstract complex cryptographic operations, simplifying encryption, decryption, signing, and verification processes.

## Challenges and Solutions

- **Handling OpenSSL APIs:** Initially struggled with the complexity of OpenSSL functions for key generation and signature verification. Solved this by relying on the provided helper functions and thoroughly reviewing the documentation.
- **Managing TLV Parsing:** Encountered issues with correctly parsing nested TLV messages, especially ensuring proper length calculations. Addressed by implementing careful boundary checks and step-by-step parsing logic.
- **Debugging HMAC Verification:** Faced difficulties in ensuring HMACs were correctly generated and verified. Resolved by adding detailed logging and validating intermediate values against expected results.
- **State Synchronization:** Ensuring both client and server maintained synchronized states during the handshake was tricky. Fixed by meticulously updating states after each successful message exchange and handling unexpected messages gracefully.

## Conclusion

While documenting the implementation was straightforward, integrating the security protocols required significant effort, particularly in managing cryptographic operations and ensuring robust message handling. The project enhanced my understanding of network security fundamentals and practical application of cryptographic techniques in network communication.

