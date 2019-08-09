#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include "client_ctrl.h"

void Input(char *user_id, char *user_pw)
{
        printf("user_id:");
        scanf("%s", user_id);
        printf("user_pw:");
        scanf("%s", user_pw);
}

int main()
{
        int ret;
        char err_res[32];

        char addr[255] = "127.0.0.1";

        //printf("address:");
        //scanf("%s", addr);

        char user_id[ID_MAX_LENGTH] = {0};
        char user_pw[PW_MAX_LENGTH] = {0};
        char help_data[BUFMAX] = {0};
        char bio_key[2 * HASHSIZE] = {0};
        memset(help_data, 1, BUFMAX);
        memset(bio_key, 2, 2*HASHSIZE);

        struct sockaddr_in server_addr;
        int sockfd;
        sockfd = client_socket_init(addr);

        char err[64];
        int interval = 3;
        memset(err, 0, sizeof(err));
        ret = anetKeepAlive(err, sockfd, interval);
        if (ret < 0)
        {
                printf("%s\n", err);
        }
        else
        {
                printf("server connected\n");

                char *us_sk;
                us_sk = (char *)malloc(HASHSIZE * sizeof(char));

                char *fun;
                fun = (char *)malloc(16 * sizeof(char));
                while (1)
                {
                        bzero(fun, 16);
                        printf("Please input fun:");
                        scanf("%s", fun);
                        if (ret < 0)
                        {
                                printf("fun send err\n");
                                return -1;
                        }

                        if (strcmp(fun, "register") == 0)
                        {
                                Input(user_id, user_pw);
                                ret = client_register(sockfd, user_id, user_pw, help_data, BUFMAX, bio_key, 2 * HASHSIZE);
                                if (ret < 0)
                                {
                                        printf("client_register err\n");
                                }
                        }
                        else if (strcmp(fun, "auth") == 0)
                        {
                                Input(user_id, user_pw);
                                ret = client_auth(sockfd, user_id, user_pw, bio_key, 2 * HASHSIZE, us_sk);
                                if (ret < 0)
                                {
                                        printf("client_auth err\n");
                                }
                        }
                        else if (strcmp(fun, "quit") == 0)
                        {
                                break;
                        }
                        else
                        {
                                printf("fun err\n");
                        }
                }

                free(fun);
                free(us_sk);
        }

        close(sockfd);
        return 0;
}

// int main()
// {
//         int ret;
//         char ip[20] = "127.0.0.1";
//         printf("Please input the ip: ");
//         scanf("%s", ip);
//         int sockfd;
//         sockfd = client_socket_init(ip);

//         char err[64];
//         int interval = 3;
//         memset(err, 0, sizeof(err));
//         ret = anetKeepAlive(err, sockfd, interval);
//         if (ret < 0)
//         {
//                 printf("%s\n", err);
//         }
//         else
//         {
//                 char fun[16] = "quit";
//                 scanf("%s", fun);
//                 client_socket_send(sockfd, fun, strlen(fun));
//         }
//         close(sockfd);
//         return 0;
// }
