# CS 118 Fall 24 Project 0

This repository serves as the starter for [CS 118's Fall 24 Project
0](https://docs.google.com/document/d/1O6IuX39E4PoMvQ9uP98AWayqCgmnoBUoRfKCUZboKwg). See the previous link for more information.


# Project 1: Reliable UDP Client-Server Implementation

## Design Choices

### Packet Structure
I used a  packet structure that includes fields for acknowledgment numbers, sequence numbers, payload length, flags (SYN/ACK), and the actual data which is limited to a maximum of 1012 bytes. This structure allows me to manage the flow of data and ensure that packets are received in order.

### Connection Management
To establish a connection, I implemented a three-way handshake similar to TCP. The client sends a SYN packet, the server responds with a SYN-ACK, and the client sends back an ACK to finalize the connection. This approach ensures that both parties are ready to communicate. The details of how sequence numbers are initialized, how the ack numbers are generated et are all done to match the spec, which can be seen in both the client and server code.

### Windowing and Retransmission
I chose a window size of 20 packets based on the spec. Each sent packet is tracked in a sending buffer with a timestamp. If an acknowledgment isn't received within the timeout period (1 second), the packet is retransmitted. This mechanism helps in dealing with packet loss.

### Non-Blocking Sockets
Both client and server sockets are set to non-blocking mode from project 0. This allows the program to handle multiple tasks simultaneously, such as sending data, receiving acknowledgments, and managing retransmissions without getting stuck waiting for any single operation.

### Diagnostic Logging
I included diagnostic messages to help with debugging and monitoring the communication process. These logs indicate when packets are sent, received, retransmitted, or identified as duplicates. This is quite similar to the reference server/client logs.

## Challenges and Solutions

### Handling Packet Loss
One of the main issues I encountered was dealing with packet loss, which is common in UDP communications. To address this, I implemented a retransmission strategy. By keeping track of sent packets and their acknowledgment status, I can resend packets that weren't acknowledged within the timeout period.

### Ensuring In-Order Delivery
Since UDP doesn't guarantee the order of packet delivery, I had to ensure that data is processed in the correct sequence. I achieved this by using sequence numbers and buffering out-of-order packets until the missing ones arrive. This way, data integrity is maintained. Sequence numbers are set based on the packet byte increments.


### Synchronizing Client and Server States
Keeping the client and server states in sync during the connection process was another challenge. I managed the state transitions (e.g., WAITING, SYN_ACK_SENT, CONNECTED) to ensure both ends of the connection were correctly aligned, preventing scenarios where one side was waiting indefinitely for a message from the other. I implemented the handshake first before breaking data into packets and sending them over.


## Conclusion

Overall, this project was a very long but good learning experience in implementing reliable communication over UDP. By carefully designing our packet structure, managing connection states, and handling common issues like packet loss and out-of-order delivery, I was able to create a robust client-server system.

