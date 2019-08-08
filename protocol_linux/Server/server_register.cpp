#include <openssl/md5.h>
#include <dlfcn.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "server_ctrl.h"

int server_register(int new_fd, MYSQL mysql)
{
        printf("server_register start!\n");

        int ret;
        char err_res[32];

        int id_len;
        int help_data_length;
        int w_auth_len;
        char *user_id;
        char *help_data;
        char *w_auth;

        user_id = (char *)malloc(ID_MAX_LENGTH * sizeof(char));
        help_data = (char *)malloc(HLDA_MAX_LENGTH * sizeof(char));
        w_auth = (char *)malloc(HASHSIZE * sizeof(char));

        memset(user_id, 0, ID_MAX_LENGTH);
        id_len = 0;
        id_len = server_socket_recv(new_fd, user_id, ID_MAX_LENGTH);
        if (id_len < 0)
        {
                free(user_id);
                free(help_data);
                free(w_auth);
                printf("user_id recv err\n");
                return id_len;
        }

        memset(help_data, 0, HLDA_MAX_LENGTH);
        help_data_length = 0;
        help_data_length = server_socket_recv(new_fd, help_data, HLDA_MAX_LENGTH);
        if (help_data_length < 0)
        {
                free(user_id);
                free(help_data);
                free(w_auth);
                printf("help_data recv err\n");
                return help_data_length;
        }

        memset(w_auth, 0, HASHSIZE);
        w_auth_len = 0;
        w_auth_len = server_socket_recv(new_fd, w_auth, HASHSIZE);
        if (w_auth_len < 0)
        {
                free(user_id);
                free(help_data);
                free(w_auth);
                printf("w_auth recv err\n");
                return w_auth_len;
        }

        ret = server_mysql_insert(mysql, user_id, id_len, help_data, help_data_length, w_auth, w_auth_len);
        if (ret < 0)
        {
                free(user_id);
                free(help_data);
                free(w_auth);
                printf("server_mysql_insert err\n");
                return -204;
        }

        char replay[RE_MAX_LENGTH];
        memset(replay, 0, RE_MAX_LENGTH);
        strcpy(replay, "register_OK");
        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
        {
                free(user_id);
                free(help_data);
                free(w_auth);
                printf("replay recv err\n");
                return ret;
        }

        free(user_id);
        free(help_data);
        free(w_auth);

        printf("server_register finished!\n");

        return 0;
}
