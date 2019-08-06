#include <errno.h>
#include <openssl/err.h>
#include "server_ctrl.h"

void server_err_msg()
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

void server_err_handle(int new_fd, int err_num)
{
        int ret;
        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);

        switch(err_num) {
        case -101:
                break;
        case -102:
                break;
        case -103:
                break;
        case -201:
                strcpy(replay, "servererr_mysql");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -202:
                strcpy(replay, "servererr_mysql");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -203:
                strcpy(replay, "servererr_mysql");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -204:
                strcpy(replay, "servererr_mysql");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -301:
                strcpy(replay, "servererr_file");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -401:
                strcpy(replay, "servererr_key");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -402:
                strcpy(replay, "servererr_encryption");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -403:
                strcpy(replay, "servererr_decryption");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -501:
                strcpy(replay, "servererr_printopts");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -601:
                strcpy(replay, "servererr_ecc");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -602:
                strcpy(replay, "servererr_bignum");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
                break;
        case -701:
                strcpy(replay, "servererr_printtask");
                ret = server_socket_send(new_fd, replay, strlen(replay));
                if (ret < 0)
                        server_err_handle(new_fd, ret);
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
