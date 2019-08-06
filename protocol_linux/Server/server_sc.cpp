#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "server_ctrl.h"

#define AES_BLOCK_NUM 80

int server_sc_send(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length)
{
        char key[EVP_MAX_KEY_LENGTH]; //保存密钥的数组
        char iv[EVP_MAX_KEY_LENGTH]; //保存初始化向量的数组
        EVP_CIPHER_CTX ctx; //EVP加密上下文环境
        char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //保存加密后密文的缓冲区数组
        int outl;
        char in[AES_BLOCK_NUM * AES_BLOCK_SIZE]; //保存明文数据和MD5值的数组
        int inl;
        int ret;
        int i;
        int total;

        char md5sum[MD5SIZE];
        bzero(md5sum, MD5SIZE);
        server_md5sum(buf, buf_len, md5sum);

        //设置key和iv
        bzero(key, EVP_MAX_KEY_LENGTH);
        bzero(iv, EVP_MAX_IV_LENGTH);
        memcpy(key, us_sk, us_sk_length);
        for(i = 0; i < EVP_MAX_IV_LENGTH; i++)
        {
                iv[i] = i;
        }

        //初始化ctx
        EVP_CIPHER_CTX_init(&ctx);

        if (us_sk_length == 16)
        {
                ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 24)
        {
                ret = EVP_EncryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 32)
        {
                ret = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else
        {
                return -401;  //key_length err
        }

        bzero(in, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        bzero(out, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);
        total = 0;
        inl = 0;
        outl = 0;

        memcpy(in, buf, buf_len);
        inl += buf_len;
        memcpy(in + inl, md5sum, MD5SIZE);
        inl += MD5SIZE;

        ret = EVP_EncryptUpdate(&ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl);//加密
        if(ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(&ctx);
                return -402;
        }
        total += outl;

        ret = EVP_EncryptFinal_ex(&ctx, (unsigned char *)out + total, &outl);
        if(ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(&ctx);
                return -402;
        }
        total += outl;

        EVP_CIPHER_CTX_cleanup(&ctx);

        ret = server_socket_send(new_fd, out, total);
        if (ret < 0)
                return ret;

        return total;
}

int server_sc_recv(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length)
{
        char key[EVP_MAX_KEY_LENGTH]; //保存密钥的数组
        char iv[EVP_MAX_KEY_LENGTH]; //保存初始化向量的数组
        EVP_CIPHER_CTX ctx;   //EVP加密上下文环境
        char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //保存解密后明文的缓冲区数组
        int outl;
        char in[AES_BLOCK_NUM * AES_BLOCK_SIZE];   //保存密文数据的数组
        int inl;
        int ret;
        int i;
        int total;
        int bufl;

        //设置key和iv
        bzero(key, EVP_MAX_KEY_LENGTH);
        bzero(iv, EVP_MAX_IV_LENGTH);
        memcpy(key, us_sk, us_sk_length);
        for(i = 0; i < EVP_MAX_IV_LENGTH; i++)
        {
                iv[i] = i;
        }

        //初始化ctx
        EVP_CIPHER_CTX_init(&ctx);

        if (us_sk_length == 16)
        {
                ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 24)
        {
                ret = EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 32)
        {
                ret = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else
        {
                return -401;        //key_length err
        }

        bzero(in, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        bzero(out, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);
        total = 0;
        inl = 0;
        outl = 0;

        inl = server_socket_recv(new_fd, in, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        if (inl < 0)
                return inl;

        ret = EVP_DecryptUpdate(&ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl);//解密
        if(ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(&ctx);
                return -403;
        }
        total += outl;

        ret = EVP_DecryptFinal_ex(&ctx, (unsigned char *)out + total, &outl);
        if(ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(&ctx);
                return -403;
        }
        total += outl;

        EVP_CIPHER_CTX_cleanup(&ctx);

        bufl = total - MD5SIZE;

        if (bufl > buf_len)
        {
                return -103;//超过缓冲区长度
        }

        bzero(buf, buf_len);
        memcpy(buf, out, bufl);

        char md5sum[MD5SIZE];
        bzero(md5sum, MD5SIZE);
        memcpy(md5sum, out + bufl, MD5SIZE);

        if (server_md5check(buf, bufl, md5sum) < 0)
        {
                return -102;//MD5校验错误，消息被篡改
        }

        return bufl;
}

int server_sc_send_file(int new_fd, char *file_path, char *us_sk, int us_sk_length)
{
        int ret;

        char *buf;
        int buf_len;
        buf = (char *)malloc(BUFMAX * sizeof(char));
        buf_len = 0;

        FILE *fpIn;
        fpIn = fopen(file_path, "rb");
        if(fpIn == NULL)
        {
                free(buf);
                return -301;
        }

        //循环读取原文，解密后后保存到明文文件。
        while(1)
        {
                bzero(buf, BUFMAX);
                buf_len = 0;
                bzero(buf, BUFMAX);
                buf_len = fread(buf, 1, BUFMAX, fpIn);
                if(buf_len <= 0) //读取原文结束
                        break;
                ret = server_sc_send(new_fd, buf, buf_len, us_sk, us_sk_length);
                if (ret < 0)
                {
                        fclose(fpIn);
                        free(buf);
                        return ret;
                }
        }

        fclose(fpIn);

        char md5sum[MD5SIZE];
        bzero(md5sum, MD5SIZE);

        buf_len = 0;
        bzero(buf, BUFMAX);
        strcpy(buf, "filend");
        buf_len = strlen(buf);
        ret = server_sc_send(new_fd, buf, buf_len, us_sk, us_sk_length);
        if (ret < 0)
        {
                free(buf);
                return ret;
        }

        server_md5sum_file(file_path, md5sum);
        ret = server_sc_send(new_fd, md5sum, MD5SIZE, us_sk, us_sk_length);
        if (ret < 0)
        {
                free(buf);
                return ret;
        }

        free(buf);
        return 0;
}

int server_sc_recv_file(int new_fd, char *file_path, char *us_sk, int us_sk_length)
{
        char *buf;
        int buf_len;
        buf = (char *)malloc(BUFMAX * sizeof(char));
        buf_len = 0;

        FILE *fpOut;

        //打开保存明文的文件
        fpOut = fopen(file_path, "wb");

        if(fpOut == NULL)
        {
                free(buf);
                return -301;
        }

        //循环读取原文，解密后后保存到明文文件。
        while(1)
        {
                buf_len = 0;
                bzero(buf, BUFMAX);
                buf_len = server_sc_recv(new_fd, buf, BUFMAX, us_sk, us_sk_length);
                if (buf_len < 0)
                {
                        free(buf);
                        return buf_len;
                }
                if(strcmp(buf, "filend") == 0)
                        break;
                fwrite(buf, 1, buf_len, fpOut);//保存明文到文件
        }

        fclose(fpOut);

        char md5sum[MD5SIZE];
        bzero(md5sum, MD5SIZE);

        buf_len = 0;
        bzero(buf, BUFMAX);
        buf_len = server_sc_recv(new_fd, buf, BUFMAX, us_sk, us_sk_length);
        if (buf_len < 0)
        {
                free(buf);
                return buf_len;
        }

        if (buf_len == MD5SIZE)
        {
                memcpy(md5sum, buf, buf_len);
        }
        else
        {
                free(buf);
                return -103;
        }

        if (server_md5check_file(file_path, md5sum) < 0)
        {
                free(buf);
                return -102;//MD5校验错误，文件被篡改
        }

        free(buf);

        return 0;
}
