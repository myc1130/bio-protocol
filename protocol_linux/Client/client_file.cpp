#include "client_ctrl.h"

int client_file_send(int sockfd, char *user_id, char *file_path, char *md5sum, char *rndnum, int rndnum_len, PrintOpts *opts, char *us_sk, int us_sk_length)
{
        int ret = 0;

        char fun[FUN_MAX_LENGTH];
        bzero(fun, sizeof(fun));
        strcpy(fun, "file_send");
        ret = client_sc_send(sockfd, fun, strlen(fun), us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send(sockfd, user_id, strlen(user_id), us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send(sockfd, file_path, strlen(file_path), us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send_file(sockfd, file_path, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send(sockfd, md5sum, MD5SIZE, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send(sockfd, rndnum, rndnum_len, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        ret = client_sc_send(sockfd, (char *)opts, sizeof(PrintOpts), us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);
        ret = client_socket_recv(sockfd, replay, RE_MAX_LENGTH);
        if (ret < 0)
        {
                printf("replay recv err\n");
                return ret;
        }
        else if (strcmp(replay, "file_OK") != 0)
        {
                printf("file send failed\n");
                return -1;
        }

        return 0;
}
