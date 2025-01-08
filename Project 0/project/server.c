#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

// Function to set a file descriptor to non-blocking mode
int make_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    // Debug: Print the original flags
    // printf("Original flags: %d\n", flags);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./server <port>\n");
        return 1;
    }

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return errno;
    }
    // printf("Socket created: %d\n", sockfd); // Debug statement

    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr)); // Zero out the structure
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections
    int port = atoi(argv[1]);
    servaddr.sin_port = htons(port); // Big endian

    // Debug: Print server address info
    // printf("Server IP: %s, Port: %d\n", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));

    /* 3. Bind the socket */
    int did_bind = bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
    if (did_bind < 0) {
        perror("bind");
        return errno;
    }
    // printf("Socket bound to port %d\n", port); // Debug statement

    /* 4. Set socket and stdin to non-blocking mode */
    if (make_non_blocking(sockfd) == -1) {
        perror("Failed to make socket non-blocking");
        return errno;
    }
    if (make_non_blocking(STDIN_FILENO) == -1) {
        perror("Failed to make stdin non-blocking");
        return errno;
    }

    /* 5. Buffer setup */
    int BUF_SIZE = 1024;
    char recv_buf[BUF_SIZE];
    char input_buf[BUF_SIZE];
    struct sockaddr_in clientaddr;
    socklen_t client_size = sizeof(clientaddr);
    int client_connected = 0;

    // int counter = 0; // Unused variable from debugging

    /* Infinite loop to handle communication */
    while (1) {
        /* 6. Receive data from client if available */
        int bytes_recvd = recvfrom(sockfd, recv_buf, BUF_SIZE, 0, (struct sockaddr*) &clientaddr, &client_size);
        if (bytes_recvd > 0) {
            // Data received from client
            client_connected = 1;
            // Debug: Print received data length
            // printf("Received %d bytes from client\n", bytes_recvd);
            write(STDOUT_FILENO, recv_buf, bytes_recvd);  // Output to stdout
        } else if (bytes_recvd == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("recvfrom");
            // break; // Uncomment to exit on error
        }

        /* Only proceed if client is connected */
        if (client_connected) {
            /* 7. Read data from stdin if available */
            int bytes_read = read(STDIN_FILENO, input_buf, BUF_SIZE);
            if (bytes_read > 0) {
                // Data read from stdin
                // printf("Read %d bytes from stdin\n", bytes_read); // Debug statement
                int did_send = sendto(sockfd, input_buf, bytes_read, 0, (struct sockaddr*) &clientaddr, client_size);
                if (did_send < 0) {
                    perror("sendto");
                    return errno;
                }
            } else if (bytes_read == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
                perror("read");
                // break; // Uncomment to exit on error
            }
        }

        // Small delay to avoid busy-waiting
        usleep(10000);  // Sleep for 10ms

        // counter++; // Increment counter (unused)
        // if (counter > 1000000) break; // Exit after some iterations (for testing)
    }

    /* 8. Close the socket */
    close(sockfd);
    return 0;
}
