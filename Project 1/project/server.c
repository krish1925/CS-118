#include <arpa/inet.h>      
#include <errno.h>          
#include <fcntl.h>        
#include <netinet/in.h>    
#include <stdbool.h>       
#include <stdio.h>        
#include <stdlib.h>        
#include <string.h>        
#include <sys/select.h>    
#include <sys/socket.h>    
#include <sys/time.h>       
#include <time.h>          
#include <unistd.h>        

#define MAX_SEGMENT_SIZE 1012      // maximum payload size
#define RETRANSMISSION_TIMEOUT 1   // retransmission time in seconds
#define MAX_WINDOW 20              // max number of packets in the window
#define PAYLOAD_BUFFER_SIZE MAX_SEGMENT_SIZE

#define DIAG_RECEIVE 0
#define DIAG_SEND 1
#define DIAG_RETRANSMIT 2
#define DIAG_DUPLICATE 3

// structure representing a network packet
typedef struct {
    uint32_t acknowledgment;
    uint32_t sequence_number;
    uint16_t payload_length;
    uint8_t flags;
    uint8_t reserved;
    uint8_t data[MAX_SEGMENT_SIZE];
} Packet;

// tracking sent packets awaiting acknowledgment
typedef struct {
    Packet packet;
    struct timeval timestamp;
} SendBufferEntry; 

// struct for buffering received packets
typedef struct {
    Packet packet;
    bool is_received;
} ReceiveBufferEntry;

// connection states
typedef enum {
    STATE_WAITING,
    STATE_SYN_ACK_SENT,
    STATE_CONNECTED
} ConnectionState;

// function to log diagnostic messages
static inline void log_diagnostic(const Packet* pkt, int event_type) {
    // checking what kind of event we're dealing with
    switch (event_type) {
        case DIAG_RECEIVE:
            fprintf(stderr, "RECEIVE");
            break;
        case DIAG_SEND:
            fprintf(stderr, "SEND");
            break;
        case DIAG_RETRANSMIT:
            fprintf(stderr, "RETRANSMIT");
            break;
        case DIAG_DUPLICATE:
            fprintf(stderr, "DUPLICATE");
            break;
        default:
            fprintf(stderr, "UNKNOWN");
    }

    // figuring out which flags are set in the packet
    bool syn_flag = pkt->flags & 0x01;
    bool ack_flag = pkt->flags & 0x02;

    // printing out the sequence, ack, length, and flags for debugging
    fprintf(stderr, "  SEQ %u ACK %u LENGTH %hu FLAGS ", ntohl(pkt->sequence_number),
            ntohl(pkt->acknowledgment), ntohs(pkt->payload_length));

    if (!syn_flag && !ack_flag) {
        fprintf(stderr, "NONE");
    } else {
        if (syn_flag) {
            fprintf(stderr, "SYN ");
        }
        if (ack_flag) {
            fprintf(stderr, "ACK ");
        }
    }
    fprintf(stderr, "\n");
}

// function to send an acknowledgment packet to the client
void send_acknowledgment(int socket_fd, struct sockaddr_in *client_addr, socklen_t addr_len, uint32_t ack_num) {
    Packet ack_pkt = {0};
    // setting the acknowledgment number
    ack_pkt.acknowledgment = htonl(ack_num);
    // setting the ack flag
    ack_pkt.flags = 0x02; // ACK flag

    // trying to send the ack packet
    if (sendto(socket_fd, &ack_pkt, sizeof(ack_pkt), 0, (struct sockaddr*)client_addr, addr_len) < 0) {
        perror("Failed to send ack");
    } else {
        // logging that we've sent an ack
        log_diagnostic(&ack_pkt, DIAG_SEND);
    }
}

int main(int argc, char **argv) {
    // making sure the user provided a port number
    if (argc < 2) {
        fprintf(stderr, "Usage: ./server <port>\n");
        exit(EXIT_FAILURE);
    }

    // seeding the random number generator for sequence numbers
    srand(time(NULL));

    // creating a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(errno);
    }

    // configure socket to be non-blocking
    int socket_flags = fcntl(sockfd, F_GETFL, 0);
    if (socket_flags < 0) {
        perror("Failed to get socket flags");
        close(sockfd);
        exit(errno);
    }
    // adding the non-blocking flag
    if (fcntl(sockfd, F_SETFL, socket_flags | O_NONBLOCK) < 0) {
        perror("Failed to set socket to non-blocking");
        close(sockfd);
        exit(errno);
    }

    // set standard input to non-blocking
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (stdin_flags < 0) {
        perror("Failed to get stdin flags");
        close(sockfd);
        exit(errno);
    }
    // adding the non-blocking flag to stdin
    if (fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK) < 0) {
        perror("Failed to set stdin to non-blocking");
        close(sockfd);
        exit(errno);
    }

    // setting up the server address structure
    struct sockaddr_in server_address = {0};
    server_address.sin_family = AF_INET; // using IPv4
    server_address.sin_addr.s_addr = INADDR_ANY; // binding to all available interfaces
    server_address.sin_port = htons(atoi(argv[1])); // setting the port from the first argument

    // binding the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Binding failed");
        close(sockfd);
        exit(errno);
    }

    // preparing to store client address info
    struct sockaddr_in client_address;
    socklen_t client_len = sizeof(client_address);

    // initializing sequence numbers and connection state
    uint32_t server_sequence = 0;
    uint32_t client_sequence = 0;
    uint32_t expected_client_seq = 0;
    uint32_t next_server_seq = 0;
    ConnectionState conn_state = STATE_WAITING;

    // setting up send and receive buffers
    SendBufferEntry send_buffer[MAX_WINDOW];
    memset(send_buffer, 0, sizeof(send_buffer));
    int outstanding_acks = 0; // keeping track of how many acks we're waiting for

    ReceiveBufferEntry recv_buffer[MAX_WINDOW];
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // main loop that runs forever
    while (1) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set); // adding the socket to the read set

        int max_fd = sockfd; // starting with the socket as the max fd

        // if we're connected and haven't hit the window limit, watch stdin
        if (conn_state == STATE_CONNECTED && outstanding_acks < MAX_WINDOW) {
            FD_SET(STDIN_FILENO, &read_set);
            if (STDIN_FILENO > max_fd) {
                max_fd = STDIN_FILENO;
            }
        }

        // setting up the timeout for select
        struct timeval select_timeout;
        select_timeout.tv_sec = RETRANSMISSION_TIMEOUT;
        select_timeout.tv_usec = 0;

        // waiting for activity on the file descriptors
        int activity = select(max_fd + 1, &read_set, NULL, NULL, &select_timeout);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }

        // checking if there's data to read on the socket
        if (FD_ISSET(sockfd, &read_set)) {
            Packet received_pkt;
            int bytes_received = recvfrom(sockfd, &received_pkt, sizeof(received_pkt), 0,
                                          (struct sockaddr *)&client_address, &client_len);
            if (bytes_received > 0) {
                uint32_t pkt_seq = ntohl(received_pkt.sequence_number);
                uint32_t pkt_ack = ntohl(received_pkt.acknowledgment);

                // handling different connection states
                if (conn_state == STATE_WAITING && (received_pkt.flags & 0x01)) {
                    // received a SYN, time to respond with SYN-ACK
                    log_diagnostic(&received_pkt, DIAG_RECEIVE);
                    server_sequence = rand() % 10000; // generating a random sequence number
                    client_sequence = pkt_seq;
                    expected_client_seq = client_sequence + 1;

                    Packet syn_ack_pkt = {0};
                    syn_ack_pkt.sequence_number = htonl(server_sequence);
                    syn_ack_pkt.acknowledgment = htonl(expected_client_seq);
                    syn_ack_pkt.flags = 0x03; // setting both SYN and ACK flags

                    // sending the SYN-ACK packet back to the client
                    if (sendto(sockfd, &syn_ack_pkt, sizeof(syn_ack_pkt), 0,
                               (struct sockaddr*)&client_address, client_len) < 0) {
                        perror("Failed to send SYN-ACK");
                    } else {
                        log_diagnostic(&syn_ack_pkt, DIAG_SEND);
                        conn_state = STATE_SYN_ACK_SENT; // moving to the next state
                    }
                }
                else if (conn_state == STATE_SYN_ACK_SENT && (received_pkt.flags & 0x02)) {
                    // received an ACK in response to our SYN-ACK
                    log_diagnostic(&received_pkt, DIAG_RECEIVE);
                    if (pkt_ack == server_sequence + 1) {
                        conn_state = STATE_CONNECTED; // connection is now established
                        fprintf(stderr, "connection established\n"); // notifying the user
                        next_server_seq = server_sequence + 1;
                    }
                }
                else if (conn_state == STATE_CONNECTED) {
                    // we're connected, so handle data or acknowledgments
                    if (received_pkt.flags & 0x02) { // if it's an ACK
                        uint32_t ack_num = pkt_ack;
                        for (int i = 0; i < MAX_WINDOW; ++i) {
                            if (send_buffer[i].packet.sequence_number != 0 &&
                                ntohl(send_buffer[i].packet.sequence_number) < ack_num) {
                                send_buffer[i].packet.sequence_number = 0; // mark as acked
                                outstanding_acks--; // reduce the count of outstanding acks
                            }
                        }
                    }

                    if (ntohs(received_pkt.payload_length) > 0) { // if there's payload data
                        uint32_t data_seq = pkt_seq;

                        if (data_seq == expected_client_seq) {
                            // it's the packet we're expecting, so process it
                            write(STDOUT_FILENO, received_pkt.data, ntohs(received_pkt.payload_length));
                            expected_client_seq += ntohs(received_pkt.payload_length);

                            // check if the next expected packets are already received
                            bool packet_found;
                            do {
                                packet_found = false;
                                for (int i = 0; i < MAX_WINDOW; ++i) {
                                    if (recv_buffer[i].is_received &&
                                        ntohl(recv_buffer[i].packet.sequence_number) == expected_client_seq) {
                                        write(STDOUT_FILENO, recv_buffer[i].packet.data, ntohs(recv_buffer[i].packet.payload_length));
                                        expected_client_seq += ntohs(recv_buffer[i].packet.payload_length);
                                        recv_buffer[i].is_received = false; // mark as processed
                                        packet_found = true;
                                    }
                                }
                            } while (packet_found);
                        }
                        else if (data_seq > expected_client_seq) {
                            // received a packet that's ahead of what we expect, buffer it
                            bool already_buffered = false;
                            for (int i = 0; i < MAX_WINDOW; ++i) {
                                if (recv_buffer[i].is_received &&
                                    ntohl(recv_buffer[i].packet.sequence_number) == data_seq) {
                                    already_buffered = true;
                                    break;
                                }
                            }
                            if (!already_buffered) {
                                for (int i = 0; i < MAX_WINDOW; ++i) {
                                    if (!recv_buffer[i].is_received) {
                                        recv_buffer[i].packet = received_pkt;
                                        recv_buffer[i].is_received = true;
                                        break;
                                    }
                                }
                            }
                        }

                        // send an acknowledgment for the next expected sequence number
                        send_acknowledgment(sockfd, &client_address, client_len, expected_client_seq);
                    }
                }
            }
        }

        // checking if there's data to read from stdin
        if (conn_state == STATE_CONNECTED && FD_ISSET(STDIN_FILENO, &read_set)) {
            if (outstanding_acks < MAX_WINDOW) { // make sure we haven't exceeded the window
                uint8_t input_data[PAYLOAD_BUFFER_SIZE];
                int bytes_read = read(STDIN_FILENO, input_data, PAYLOAD_BUFFER_SIZE);
                if (bytes_read > 0) {
                    // creating a data packet to send
                    Packet data_pkt = {0};
                    data_pkt.sequence_number = htonl(next_server_seq);
                    data_pkt.acknowledgment = htonl(expected_client_seq);
                    data_pkt.payload_length = htons(bytes_read);
                    data_pkt.flags = 0x02; // setting the ACK flag

                    // copying the input data into the packet
                    memcpy(data_pkt.data, input_data, bytes_read);

                    // sending the data packet to the client
                    if (sendto(sockfd, &data_pkt, sizeof(Packet), 0,
                               (struct sockaddr *)&client_address, client_len) < 0) {
                        perror("Failed to send data packet");
                    } else {
                        log_diagnostic(&data_pkt, DIAG_SEND);
                    }

                    // adding the packet to the send buffer for tracking
                    for (int i = 0; i < MAX_WINDOW; ++i) {
                        if (send_buffer[i].packet.sequence_number == 0) { // finding an empty spot
                            send_buffer[i].packet = data_pkt;
                            gettimeofday(&send_buffer[i].timestamp, NULL); // recording the send time
                            outstanding_acks++; // incrementing the count of outstanding acks
                            next_server_seq += bytes_read; // updating the next sequence number
                            break;
                        }
                    }
                }
            }
        }

        // checking for any packets that need to be retransmitted
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        for (int i = 0; i < MAX_WINDOW; ++i) {
            if (send_buffer[i].packet.sequence_number != 0) { // if there's a packet waiting for ack
                long elapsed_sec = current_time.tv_sec - send_buffer[i].timestamp.tv_sec;
                long elapsed_usec = current_time.tv_usec - send_buffer[i].timestamp.tv_usec;
                if (elapsed_usec < 0) { // adjusting if microseconds are negative
                    elapsed_sec -= 1;
                    elapsed_usec += 1000000;
                }

                if (elapsed_sec >= RETRANSMISSION_TIMEOUT) { // if it's time to retransmit
                    // retransmitting the packet
                    if (sendto(sockfd, &send_buffer[i].packet, sizeof(Packet), 0,
                               (struct sockaddr *)&client_address, client_len) < 0) {
                        perror("Failed to retransmit packet");
                    } else {
                        log_diagnostic(&send_buffer[i].packet, DIAG_RETRANSMIT);
                        gettimeofday(&send_buffer[i].timestamp, NULL); // resetting the send time
                    }
                }
            }
        }
    }

    // closing the socket when done
    close(sockfd);
    return 0;
}
