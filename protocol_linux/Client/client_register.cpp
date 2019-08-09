#include <openssl/crypto.h>
#include <openssl/md5.h>
#include "client_ctrl.h"

int client_register(int sockfd, char *user_id, char *user_pw, char *help_data, int help_data_length, char *bio_key, int bio_key_length)
{
        /* Define variables */
        size_t hash_in_len = 0;
        int ret = 0;
        int result = 0;

        char err_res[32] = {0};
        char fun[FUN_MAX_LENGTH] = "register";
        char replay[RE_MAX_LENGTH] = {0};

        char *w_auth = NULL;
        char *hash_in = NULL;

        /* Register start */
        printf("client_register start!\n");

        ret = client_socket_send(sockfd, fun, strlen(fun));
        if (ret < 0)
                return ret;

        w_auth = (char *)malloc(HASHSIZE * sizeof(char));
        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        memset(hash_in, 0, 3 * BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, bio_key, &hash_in_len, bio_key_length);
        client_memcat(hash_in, user_pw, &hash_in_len, strlen(user_pw));

        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)w_auth);

        ret = client_socket_send(sockfd, user_id, strlen(user_id));
        if (ret < 0)
        {
                printf("user_id send err\n");
                result = ret;
                goto end;
        }

        ret = client_socket_send(sockfd, help_data, help_data_length);
        if (ret < 0)
        {
                printf("help_data send err\n");
                result = ret;
                goto end;
        }

        ret = client_socket_send(sockfd, w_auth, HASHSIZE);
        if (ret < 0)
        {
                printf("w_auth send err\n");
                result = ret;
                goto end;
        }

        memset(replay, 0, RE_MAX_LENGTH);
        ret = client_socket_recv(sockfd, replay, RE_MAX_LENGTH);
        if (ret < 0)
        {
                printf("replay recv err\n");
                result = ret;
                goto end;
        }
        else if (strcmp(replay, "register_OK") != 0)
        {
                printf("register failed\n");
                result = -1;
                goto end;
        }

end:
        if (w_auth != NULL)
        {
                free(w_auth);
                w_auth = NULL;
        }

        if (hash_in != NULL)
        {
                free(hash_in);
                hash_in = NULL;
        }

        printf("client_register finished!\n");

        return result;
}
