#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include "client_ctrl.h"

int main()
{
        int ret;
        char ip[20] = "192.168.111.17";
        int sockfd;
        sockfd = client_socket_init(ip);

        char err[64];
        int interval = 3;
        bzero(err, sizeof(err));
        ret = anetKeepAlive(err, sockfd, interval);
        if (ret < 0)
        {
                printf("%s\n", err);
        }
        else
        {
                char fun[16] = "quit";
                scanf("%s", fun);
                client_socket_send(sockfd, fun, strlen(fun));
        }
        close(sockfd);
        return 0;
}
