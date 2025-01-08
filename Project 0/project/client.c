#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

// Function to set a file descriptor to non-blocking mode
int make_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    // printf("Original flags: %d\n", flags);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./client <hostname> <port>\n");
        return 1;
    }

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return errno;
    }
    // printf("Socket created: %d\n", sockfd); // Debug statement

    /* 2. Construct server address */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr)); // Zero out the structure
    serveraddr.sin_family = AF_INET; // use IPv4
    int port = atoi(argv[2]);
    serveraddr.sin_port = htons(port); // Big endian

    /* Resolve hostname */
    if (strcmp(argv[1], "localhost") == 0) {
        serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        struct hostent *host = gethostbyname(argv[1]);
        if (host == NULL) {
            fprintf(stderr, "Error resolving hostname %s\n", argv[1]);
            return 1;
        }
        memcpy(&serveraddr.sin_addr, host->h_addr_list[0], host->h_length);
    }

    // Debug: Print server address info
    // printf("Server IP: %s, Port: %d\n", inet_ntoa(serveraddr.sin_addr), ntohs(serveraddr.sin_port));

    /* 3. Set socket and stdin to non-blocking mode */
    if (make_non_blocking(sockfd) == -1) {
        perror("Failed to make socket non-blocking");
        return errno;
    }
    if (make_non_blocking(STDIN_FILENO) == -1) {
        perror("Failed to make stdin non-blocking");
        return errno;
    }

    /* 4. Buffer setup */
    int BUF_SIZE = 1024;
    char recv_buf[BUF_SIZE];
    char input_buf[BUF_SIZE];
    socklen_t server_size = sizeof(serveraddr);

    // int test_var = 42; 

    /* Infinite loop to handle communication */
    while (1) {
        /* 5. Receive data from server if available */
        int bytes_recvd = recvfrom(sockfd, recv_buf, BUF_SIZE, 0, NULL, NULL);
        if (bytes_recvd > 0) {
            // Data received from server
            // printf("Received %d bytes from server\n", bytes_recvd); // Debug statement
            write(STDOUT_FILENO, recv_buf, bytes_recvd);  // Output to stdout
        } else if (bytes_recvd == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("recvfrom");
            // break; // Uncomment to exit on error
        }

        /* 6. Read data from stdin if available */
        int bytes_read = read(STDIN_FILENO, input_buf, BUF_SIZE);
        if (bytes_read > 0) {
            // Data read from stdin
            // printf("Read %d bytes from stdin\n", bytes_read); // Debug statement
            int did_send = sendto(sockfd, input_buf, bytes_read, 0, (struct sockaddr*) &serveraddr, server_size);
            if (did_send < 0) {
                perror("sendto");
                return errno;
            }
        } else if (bytes_read == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("read");
            // break; // exit on error
        }

        // Small delay to avoid busy-waiting
        usleep(10000);  // Sleep for 10ms

        // if (test_var == 42) {
        //     // printf("blahhhhhhh.\n");
        // }
    }

    /* 7. Close the socket */
    close(sockfd);
    return 0;
}
