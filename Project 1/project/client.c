#include <stdio.h> // standard io stuff
#include <stdlib.h> // for exit and stuff
#include <string.h> // dealing with strings
#include <unistd.h> // for close and usleep
#include <errno.h> // error numbers, ugh
#include <fcntl.h> // file control options
#include <stdbool.h> // booleans, yay
#include <time.h> // time functions
#include <sys/time.h> // more time stuff
#include <sys/socket.h> // socket programming
#include <sys/select.h> // for select function
#include <arpa/inet.h> // inet functions


#define MSS 1012               // maximum segment size, kinda important
#define MAX_PAYLOAD_SIZE MSS   // max payload same as mss
#define TIMEOUT_SEC 3          // timeout for retries, not too long
#define RETRY_DELAY_USEC 1000000 // wait a sec before retrying
#define WINDOW_SIZE 20         // window size for packets


// packet flags, simple stuff
#define FLAG_SYN 0x01
#define FLAG_ACK 0x02

// diagnostic message types, for logging
#define DIAG_RECEIVE 0
#define DIAG_SEND 1
#define DIAG_RETRANSMIT 2
#define DIAG_DUPLICATE  3

// packet structure, holds all packet info
typedef struct {
    uint32_t ack;              // acknowledgment number
    uint32_t seq;              // sequence number
    uint16_t length;           // payload length
    uint8_t flags;             // syn/ack flags
    uint8_t unused;            // just padding
    uint8_t payload[MSS];      // the actual data
} packet_t;

// sending buffer entry, keeps track of sent packets
typedef struct {
    packet_t pkt;
    struct timeval sent_time; // when it was sent
} send_buffer_entry_t;

// receiving buffer entry, for incoming packets
typedef struct {
    packet_t pkt;
    bool received; // if it's been received
} recv_buffer_entry_t;

// function to print diagnostic messages, kinda messy
static inline void print_diagnostic(packet_t* pkt, int diag_type) {
    // checking what kind of event we're dealing with
    switch (diag_type) {
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


    // check flags
    bool syn = pkt->flags & FLAG_SYN;
    bool ack = pkt->flags & FLAG_ACK;

    // print seq, ack, size, flags
    fprintf(stderr, " %u ack %u size %hu flags ", ntohl(pkt->seq),
            ntohl(pkt->ack), ntohs(pkt->length));

    if (!syn && !ack) {
        fprintf(stderr, "none");
    } else {
        if (syn) {
            fprintf(stderr, "syn ");
        }
        if (ack) {
            fprintf(stderr, "ack ");
        }
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: client <hostname> <port>\n"); // usage message
        exit(EXIT_FAILURE); // exit if not enough args
    }

    // create udp socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed"); // oops
        exit(errno); // exit on error
    }

    // set socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("failed to set non-blocking mode"); // can't set non-blocking
        close(sockfd); // close socket
        exit(errno); // exit
    }

    // construct server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr)); // zero it out
    server_addr.sin_family = AF_INET;
    // check if hostname is "localhost"
    if (strcmp(argv[1], "localhost") == 0) {
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // local addr
    } else {
        server_addr.sin_addr.s_addr = inet_addr(argv[1]); // other addr
    }
    int port = atoi(argv[2]); // get port
    server_addr.sin_port = htons(port); // set port
    socklen_t addr_len = sizeof(server_addr); // addr length

    // seed random number generator for seq nums
    srand(time(NULL));
    uint32_t client_seq = rand() % 1000;  // initial client seq num
    uint32_t server_seq = 0; // server seq starts at 0

    // step 1: send syn packet to initiate handshake
    packet_t syn_packet = {0};
    syn_packet.seq = htonl(client_seq);
    syn_packet.flags = FLAG_SYN;  // set syn flag

    for (int attempt = 0; attempt < TIMEOUT_SEC; ++attempt) {
        // send syn packet
        if (sendto(sockfd, &syn_packet, sizeof(syn_packet), 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("send syn failed"); // send failed
            close(sockfd); // close socket
            exit(errno); // exit
        }
        print_diagnostic(&syn_packet, DIAG_SEND);  // log the send

        // attempt to receive syn-ack packet
        packet_t syn_ack_packet = {0};
        int bytes_received = recvfrom(sockfd, &syn_ack_packet, sizeof(syn_ack_packet), 0,
                                      (struct sockaddr *)&server_addr, &addr_len);

        if (bytes_received > 0) {
            server_seq = ntohl(syn_ack_packet.seq); // get server seq
            print_diagnostic(&syn_ack_packet, DIAG_RECEIVE);  // log receive
            // check if both syn and ack flags are set
            if ((syn_ack_packet.flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK)) {
                break;  // exit retry loop if syn-ack received
            }
        }

        // wait before retrying
        usleep(RETRY_DELAY_USEC);
        fprintf(stderr, "retrying syn...\n"); // retry message
    }

    // step 2: send final ack to complete handshake
    packet_t ack_packet = {0};
    ack_packet.seq = htonl(client_seq + 1);
    ack_packet.ack = htonl(server_seq + 1);
    ack_packet.flags = FLAG_ACK;  // set ack flag

    if (sendto(sockfd, &ack_packet, sizeof(ack_packet), 0,
               (struct sockaddr *)&server_addr, addr_len) < 0) {
        perror("send final ack failed"); // send failed
        close(sockfd); // close socket
        exit(errno); // exit
    }
    print_diagnostic(&ack_packet, DIAG_SEND);  // log the ack

    // handshake completed
    fprintf(stderr, "handshake completed\n"); // done with handshake

    // initialize sending buffer
    send_buffer_entry_t send_buffer[WINDOW_SIZE];
    memset(send_buffer, 0, sizeof(send_buffer)); // zero it out
    int unack_packets = 0; // count of unacknowledged packets
    uint32_t next_seq_num = client_seq + 1;  // next seq num

    // initialize receiving buffer
    recv_buffer_entry_t recv_buffer[WINDOW_SIZE];
    memset(recv_buffer, 0, sizeof(recv_buffer)); // zero it out
    uint32_t expected_seq_num = server_seq + 1;  // next expected seq from server

    // initialize select parameters
    fd_set read_fds;
    struct timeval timeout;
    int max_fd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO; // max fd

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);          // add socket to read set
        FD_SET(STDIN_FILENO, &read_fds);    // add stdin to read set

        // set timeout for select
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // wait for activity
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) {
            perror("select error"); // select failed
            break; // exit loop
        }

        // handle incoming packets
        if (FD_ISSET(sockfd, &read_fds)) {
            packet_t incoming_packet;
            int bytes_received = recvfrom(sockfd, &incoming_packet, sizeof(incoming_packet), 0,
                                          (struct sockaddr *)&server_addr, &addr_len);
            if (bytes_received > 0) {
                print_diagnostic(&incoming_packet, DIAG_RECEIVE);  // log received packet

                // check if it's an ack packet
                if (incoming_packet.flags & FLAG_ACK) {
                    uint32_t ack_num = ntohl(incoming_packet.ack);
                    // remove acknowledged packets from send buffer
                    for (int i = 0; i < WINDOW_SIZE; ++i) {
                        if (send_buffer[i].pkt.seq != 0 &&
                            ntohl(send_buffer[i].pkt.seq) < ack_num) {
                            send_buffer[i].pkt.seq = 0;  // mark as acked
                            unack_packets--;
                        }
                    }
                }

                // check if it's a data packet
                if (!(incoming_packet.flags & FLAG_SYN) && incoming_packet.length > 0) {
                    uint32_t pkt_seq = ntohl(incoming_packet.seq);
                    uint16_t pkt_length = ntohs(incoming_packet.length);

                    // if packet has expected seq num
                    if (pkt_seq == expected_seq_num) {
                        // write payload to stdout
                        write(STDOUT_FILENO, incoming_packet.payload, pkt_length);
                        expected_seq_num += pkt_length;

                        // check for buffered packets that can now be processed
                        bool found;
                        do {
                            found = false;
                            for (int i = 0; i < WINDOW_SIZE; ++i) {
                                if (recv_buffer[i].received &&
                                    ntohl(recv_buffer[i].pkt.seq) == expected_seq_num) {
                                    write(STDOUT_FILENO, recv_buffer[i].pkt.payload,
                                          ntohs(recv_buffer[i].pkt.length));
                                    expected_seq_num += ntohs(recv_buffer[i].pkt.length);
                                    recv_buffer[i].received = false;  // remove from buffer
                                    found = true;
                                }
                            }
                        } while (found);
                    } else if (pkt_seq > expected_seq_num) {
                        // buffer out-of-order packet
                        bool already_buffered = false;
                        for (int i = 0; i < WINDOW_SIZE; ++i) {
                            if (recv_buffer[i].received &&
                                ntohl(recv_buffer[i].pkt.seq) == pkt_seq) {
                                already_buffered = true;
                                break;
                            }
                        }
                        if (!already_buffered) {
                            for (int i = 0; i < WINDOW_SIZE; ++i) {
                                if (!recv_buffer[i].received) {
                                    recv_buffer[i].pkt = incoming_packet;
                                    recv_buffer[i].received = true;
                                    break;
                                }
                            }
                        }
                    }

                    // send ack for the next expected seq num
                    packet_t ack_response = {0};
                    ack_response.ack = htonl(expected_seq_num);
                    ack_response.flags = FLAG_ACK;  // set ack flag

                    if (sendto(sockfd, &ack_response, sizeof(ack_response), 0,
                               (struct sockaddr *)&server_addr, addr_len) < 0) {
                        perror("send ack failed"); // send failed
                        close(sockfd); // close socket
                        exit(errno); // exit
                    }
                    print_diagnostic(&ack_response, DIAG_SEND);  // log the ack send
                }
            }
        }

        // handle data from stdin
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            // check if window is not full
            if (unack_packets < WINDOW_SIZE) {
                // read data from stdin
                uint8_t data_buffer[MAX_PAYLOAD_SIZE];
                ssize_t bytes_read = read(STDIN_FILENO, data_buffer, MAX_PAYLOAD_SIZE);
                if (bytes_read > 0) {
                    // prepare data packet
                    packet_t data_packet = {0};
                    data_packet.seq = htonl(next_seq_num);
                    data_packet.ack = htonl(expected_seq_num);  // optional ack
                    data_packet.length = htons(bytes_read);
                    data_packet.flags = FLAG_ACK;  // set ack flag

                    memcpy(data_packet.payload, data_buffer, bytes_read);

                    // send data packet
                    if (sendto(sockfd, &data_packet, sizeof(data_packet), 0,
                               (struct sockaddr *)&server_addr, addr_len) < 0) {
                        perror("send data packet failed"); 
                        close(sockfd); // close socket
                        exit(errno); // exit
                    }
                    print_diagnostic(&data_packet, DIAG_SEND);  // log the send

                    // add to sending buffer
                    for (int i = 0; i < WINDOW_SIZE; ++i) {
                        if (send_buffer[i].pkt.seq == 0) {  // empty slot
                            send_buffer[i].pkt = data_packet;
                            gettimeofday(&send_buffer[i].sent_time, NULL);  // record send time
                            unack_packets++;
                            next_seq_num += bytes_read;  // update seq num
                            break;
                        }
                    }
                }
            }
        }

        // handle retransmissions
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        for (int i = 0; i < WINDOW_SIZE; ++i) {
            if (send_buffer[i].pkt.seq != 0) {  // packet is in buffer
                // calculate elapsed time
                time_t elapsed_sec = current_time.tv_sec - send_buffer[i].sent_time.tv_sec;
                suseconds_t elapsed_usec = current_time.tv_usec - send_buffer[i].sent_time.tv_usec;
                if (elapsed_usec < 0) {
                    elapsed_sec -= 1;
                    elapsed_usec += 1000000;
                }
                // check if timeout exceeded
                if (elapsed_sec >= TIMEOUT_SEC) {
                    // retransmit packet
                    if (sendto(sockfd, &send_buffer[i].pkt, sizeof(packet_t), 0,
                               (struct sockaddr *)&server_addr, addr_len) < 0) {
                        perror("retransmit data packet failed"); // send failed
                        close(sockfd); // close socket
                        exit(errno); // exit
                    }
                    print_diagnostic(&send_buffer[i].pkt, DIAG_SEND);  // log retransmission
                    // update sent_time
                    gettimeofday(&send_buffer[i].sent_time, NULL);
                }
            }
        }
    }

    close(sockfd); // close socket when done
    return 0; // end program
}
