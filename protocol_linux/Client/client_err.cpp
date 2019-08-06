#include <errno.h>
#include <openssl/err.h>
#include "client_ctrl.h"

void client_err_msg()
{
        //加载错误信息
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();
        // 获取错误号
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        char *pTmp = NULL;
        // 格式：error:errId:库:函数:原因
        pTmp = ERR_error_string(ulErr,szErrMsg);
        printf("%s\n", szErrMsg);
}

void client_err_handle(int sockfd, int err_num)
{
        int ret;
        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);

        switch(err_num) {
        case -1:
                break;
        case -101:
                break;
        case -102:
                break;
        case -103:
                break;
        case -201:
                strcpy(replay, "clienterr_mysql");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -202:
                strcpy(replay, "clienterr_mysql");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -203:
                strcpy(replay, "clienterr_mysql");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -204:
                strcpy(replay, "clienterr_mysql");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -301:
                strcpy(replay, "clienterr_file");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -401:
                strcpy(replay, "clienterr_key");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -402:
                strcpy(replay, "clienterr_encryption");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -403:
                strcpy(replay, "clienterr_decryption");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -501:
                strcpy(replay, "clienterr_printopts");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -601:
                strcpy(replay, "clienterr_ecc");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -602:
                strcpy(replay, "clienterr_bignum");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -701:
                strcpy(replay, "clienterr_printtask");
                ret = client_socket_send(sockfd, replay, strlen(replay));
                if (ret < 0)
                        client_err_handle(sockfd, ret);
                break;
        case -801:
                break;
        case -802:
                break;
        case -901:
                break;
        default:
                break;
        }
}
