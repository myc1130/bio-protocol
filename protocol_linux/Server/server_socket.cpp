#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include "server_ctrl.h"

ssize_t readn(int fd, void *buf, size_t count)
{
        int left = count; //the left bytes
        char *ptr = (char *)buf;
        while (left > 0)
        {
                int readBytes = read(fd, ptr, left);
                if (readBytes < 0) //the return of read function has two situations：1.interrupt 2.error
                {
                        if (errno == EINTR) //read interrupt
                        {
                                continue;
                        }
                        return -1;
                }
                if (readBytes == 0) //read the EOF
                {
                        //the other side close
                        printf("peer close\n");
                        return count - left;
                }
                left -= readBytes;
                ptr += readBytes;
        }
        return count;
}

/*
   writen function
   write count bytes
 */
ssize_t writen(int fd, void *buf, size_t count)
{
        int left = count;
        char *ptr = (char *)buf;
        while (left > 0)
        {
                int writeBytes = write(fd, ptr, left);
                if (writeBytes < 0)
                {
                        if (errno == EINTR)
                                continue;
                        return -1;
                }
                else if (writeBytes == 0)
                        continue;
                left -= writeBytes;
                ptr += writeBytes;
        }
        return count;
}

struct packet
{
        unsigned int msgLen;
        char data[8192];
};

int server_socket_send(int new_fd, char *buf, size_t buf_len)
{
        int len;
        struct packet writebuf;
        memset(&writebuf, 0, sizeof(writebuf));
        int n = buf_len;
        writebuf.msgLen = htonl(n);
        memcpy(writebuf.data, buf, buf_len);
        len = writen(new_fd, &writebuf, 4 + n);
        if (len <= 0)
        {
                printf("Message '");
                server_output(buf, buf_len);
                printf("' send failed! Error number is %d, error message is '%s'\n", errno, strerror(errno));
                return -102;
        }
        else
        {
                printf("Message '");
                server_output(buf, buf_len);
                printf("' send successfully, totally %d Bytes\n", len);
                return len;
        }
}

int server_socket_recv(int new_fd, char *buf, size_t buf_len)
{
        int len;
        struct packet readbuf;
        memset(&readbuf, 0, sizeof(readbuf));
        int ret = readn(new_fd, &readbuf.msgLen, 4);
        int dataBytes = ntohl(readbuf.msgLen);
        len = readn(new_fd, buf, dataBytes);
        if (len > 0)
        {
                printf("Message '");
                server_output(buf, len);
                printf("' accepted successfully, totally %d Bytes\n", len);
                if (strncmp(buf, "clienterr_", 10) == 0)
                {
                        server_err_handle(new_fd, -901);
                        return -901;
                }
                else if (strcmp(buf, "client_failed") == 0)
                {
                        return -1;
                }
                return len;
        }
        else
        {
                printf("Message accepted failed! Error number is %d, error message is '%s'\n", errno, strerror(errno));
                return -102;
        }
}

int server_socket_init()
{
        struct sockaddr_in server_addr;
        int sockfd;

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                perror("socket");
                return -101;
        }

        int reuse = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        {
                perror("setsockopt");
                return -101;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
                perror("bind");
                return -101;
        }

        if (listen(sockfd, 10) < 0)
        {
                perror("listen");
                return -101;
        }

        return sockfd;
}

/* Set TCP keep alive option to detect dead peers. The interval option
 * is only used for Linux as we are using Linux-specific APIs to set
 * the probe send time, interval, and count. */
int anetKeepAlive(char *err, int fd, int interval)
{
        int val = 1;
        //Open keepalive
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
        {
                sprintf(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
                return -1;
        }

        /* Default settings are more or less garbage, with the keepalive time
         * set to 7200 by default on Linux. Modify settings to make the feature
         * actually useful. */

        /* Send first probe after interval. */
        val = interval;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) //macOS:TCP_KEEPALIVE; linux:TCP_KEEPIDLE
        {
                sprintf(err, "setsockopt TCP_KEEPALIVE: %s\n", strerror(errno));
                return -1;
        }

        /* Send next probes after the specified interval. Note that we set the
         * delay as interval / 3, as we send three probes before detecting
         * an error (see the next setsockopt call). */
        val = interval / 3;
        if (val == 0)
                val = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0)
        {
                sprintf(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
                return -1;
        }

        /* Consider the socket in error state after three we send three ACK
         * probes without getting a reply. */
        val = 3;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0)
        {
                sprintf(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
                return -1;
        }

        return 0;
}
