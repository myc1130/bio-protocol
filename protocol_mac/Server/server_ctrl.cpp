#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include <mysql/mysql.h>
#include "server_ctrl.h"

int main()
{
        MYSQL mysql;

        mysql = server_mysql_init();

        printf("mysql init finished\n");

        int sockfd;

        sockfd = server_socket_init();

        if (sockfd < 0)
        {
                mysql_close(&mysql);
                return 0;
        }

        while (1)
        {
                printf("server is listening\n");

                struct sockaddr_in client_addr;
                int len, new_fd;
                len = sizeof(client_addr);

                new_fd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&len);
                if (new_fd < 0)
                {
                        perror("accept");
                        return -101;
                }
                printf("server: got connection from %s, port %d, socket %d\n",
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
                       new_fd);

                pid_t pid = fork();
                if (pid < 0)
                {
                        perror("fork");
                        _exit(-1);
                }
                else if (pid == 0)
                {
                        close(sockfd);

                        int ret;
                        char err[64];
                        int interval = 3;
                        memset(err, 0, sizeof(err));
                        ret = anetKeepAlive(err, new_fd, interval);
                        if (ret < 0)
                        {
                                printf("%s\n", err);
                                break;
                        }

                        char *us_sk;
                        us_sk = (char *)malloc(HASHSIZE * sizeof(char));

                        char *fun;
                        fun = (char *)malloc(FUN_MAX_LENGTH * sizeof(char));

                        int flag = 0;

                        while (1)
                        {
                                printf("Waiting for function......");
                                memset(fun, 0, FUN_MAX_LENGTH);
                                if (!flag)
                                {
                                        ret = server_socket_recv(new_fd, fun, FUN_MAX_LENGTH);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                break;
                                        }
                                }
                                else
                                {
                                        ret = server_sc_recv(new_fd, fun, FUN_MAX_LENGTH, us_sk, MD5SIZE);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                break;
                                        }
                                }

                                if (strcmp(fun, "register") == 0)
                                {
                                        ret = server_register(new_fd, mysql);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                continue;
                                        }
                                }
                                else if (strcmp(fun, "auth") == 0)
                                {
                                        memset(us_sk, 0, HASHSIZE);
                                        ret = server_auth(new_fd, mysql, us_sk);
                                        if (ret < 0)
                                        {
                                                if (ret == -1)
                                                {
                                                        char replay[RE_MAX_LENGTH] = "server_failed";
                                                        ret = server_socket_send(new_fd, replay, strlen(replay));
                                                        if (ret < 0)
                                                        {
                                                                server_err_handle(new_fd, ret);
                                                                break;
                                                        }
                                                }
                                                else
                                                {
                                                        server_err_handle(new_fd, ret);
                                                        continue;
                                                }
                                        }
                                        flag = 1;
                                }
                                else if (strcmp(fun, "mysql_inquire") == 0)
                                {
                                        ret = server_mysql_inquire(new_fd, mysql);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                continue;
                                        }
                                }
                                else if (strcmp(fun, "get_helpdata") == 0)
                                {
                                        ret = server_mysql_gethelpdata(new_fd, mysql);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                continue;
                                        }
                                }
                                else if (strcmp(fun, "file_send") == 0)
                                {
                                        ret = server_file_recv(new_fd, mysql, us_sk, MD5SIZE);
                                        if (ret < 0)
                                        {
                                                server_err_handle(new_fd, ret);
                                                continue;
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
                        close(new_fd);
                        printf("Client %s quit\n", inet_ntoa(client_addr.sin_addr));
                        exit(0);
                }
                else if (pid > 0)
                {
                        close(new_fd);
                }
        }

        mysql_close(&mysql);
        close(sockfd);

        return 0;
}
