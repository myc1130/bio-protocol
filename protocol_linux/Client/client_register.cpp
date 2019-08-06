#include <openssl/crypto.h>
#include <openssl/md5.h>
#include "client_ctrl.h"

int client_register(int sockfd, char *user_id, char *user_pw, char *help_data, int help_data_length, char *bio_key, int bio_key_length)
{
        printf("client_register start!\n");
        int ret;

        char fun[FUN_MAX_LENGTH] = "register";
        ret = client_socket_send(sockfd, fun, strlen(fun));
        if (ret < 0)
                return ret;

        char err_res[32];

        char *w_auth;

        w_auth = (char *)malloc(HASHSIZE * sizeof(char));

        size_t hash_in_len;
        char *hash_in;
        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, bio_key, &hash_in_len, bio_key_length);
        client_memcat(hash_in, user_pw, &hash_in_len, strlen(user_pw));

        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)w_auth);

        ret = client_socket_send(sockfd, user_id, strlen(user_id));
        if (ret < 0)
        {
                free(w_auth);
                free(hash_in);
                printf("user_id send err\n");
                return ret;
        }

        ret = client_socket_send(sockfd, help_data, help_data_length);
        if (ret < 0)
        {
                free(w_auth);
                free(hash_in);
                printf("help_data send err\n");
                return ret;
        }

        ret = client_socket_send(sockfd, w_auth, HASHSIZE);
        if (ret < 0)
        {
                free(w_auth);
                free(hash_in);
                printf("w_auth send err\n");
                return ret;
        }

        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);
        ret = client_socket_recv(sockfd, replay, RE_MAX_LENGTH);
        if (ret < 0)
        {
                free(w_auth);
                free(hash_in);
                printf("replay recv err\n");
                return ret;
        }
        else if (strcmp(replay, "register_OK") != 0)
        {
                free(w_auth);
                free(hash_in);
                printf("register failed\n");
                return -1;
        }

        free(w_auth);
        free(hash_in);

        printf("client_register finished!\n");

        return 0;
}
