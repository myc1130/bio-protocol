#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "server_ctrl.h"

#define AES_BLOCK_NUM 80

int server_sc_send(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length)
{
        char key[EVP_MAX_KEY_LENGTH];                              //the array to keep key
        char iv[EVP_MAX_KEY_LENGTH];                               //the array to keep iv
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();                //EVP Cipher CTX
        char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //the array to keep cipher
        int outl;
        char in[AES_BLOCK_NUM * AES_BLOCK_SIZE]; //the array to keep plain and MD
        int inl;
        int ret;
        int i;
        int total;

        char md5sum[MD5SIZE];
        memset(md5sum, 0, MD5SIZE);
        server_md5sum(buf, buf_len, md5sum);

        //Set key and iv
        memset(key, 0, EVP_MAX_KEY_LENGTH);
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        memcpy(key, us_sk, us_sk_length);
        for (i = 0; i < EVP_MAX_IV_LENGTH; i++)
        {
                iv[i] = i;
        }

        //Initialize ctx
        EVP_CIPHER_CTX_init(ctx);

        if (us_sk_length == 16)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 24)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 32)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else
        {
                return -401; //key_length err
        }

        memset(in, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        memset(out, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);
        total = 0;
        inl = 0;
        outl = 0;

        memcpy(in, buf, buf_len);
        inl += buf_len;
        memcpy(in + inl, md5sum, MD5SIZE);
        inl += MD5SIZE;

        ret = EVP_EncryptUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl); //encrypt
        if (ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -402;
        }
        total += outl;

        ret = EVP_EncryptFinal_ex(ctx, (unsigned char *)out + total, &outl);
        if (ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -402;
        }
        total += outl;

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        ret = server_socket_send(new_fd, out, total);
        if (ret < 0)
                return ret;

        return total;
}

int server_sc_recv(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length)
{   
        char key[EVP_MAX_KEY_LENGTH];                              //the array to keep key
        char iv[EVP_MAX_KEY_LENGTH];                               //the array to keep iv
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();                //EVP Cipher CTX
        char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //the array to keep plain and MD
        int outl;
        char in[AES_BLOCK_NUM * AES_BLOCK_SIZE]; //the array to keep cipher
        int inl;
        int ret;
        int i;
        int total;
        int bufl;

        //Set key and iv
        memset(key, 0, EVP_MAX_KEY_LENGTH);
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        memcpy(key, us_sk, us_sk_length);
        for (i = 0; i < EVP_MAX_IV_LENGTH; i++)
        {
                iv[i] = i;
        }

        //Initialize ctx
        EVP_CIPHER_CTX_init(ctx);

        if (us_sk_length == 16)
        {
                ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 24)
        {
                ret = EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (us_sk_length == 32)
        {
                ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else
        {
                return -401; //key_length err
        }

        memset(in, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        memset(out, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);
        total = 0;
        inl = 0;
        outl = 0;

        inl = server_socket_recv(new_fd, in, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        if (inl < 0)
                return inl;

        ret = EVP_DecryptUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl); //decrypt
        if (ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -403;
        }
        total += outl;

        ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)out + total, &outl);
        if (ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -403;
        }
        total += outl;

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        bufl = total - MD5SIZE;

        if (bufl > buf_len)
        {
                return -103; //Exceeded buffer length
        }

        memset(buf, 0, buf_len);
        memcpy(buf, out, bufl);

        char md5sum[MD5SIZE];
        memset(md5sum, 0, MD5SIZE);
        memcpy(md5sum, out + bufl, MD5SIZE);

        if (server_md5check(buf, bufl, md5sum) < 0)
        {
                return -102; //MD5 check error，message has been changed
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
        if (fpIn == NULL)
        {
                free(buf);
                return -301;
        }

        //Cycle read plain, encrypt and send
        while (1)
        {
                memset(buf, 0, BUFMAX);
                buf_len = 0;
                memset(buf, 0, BUFMAX);
                buf_len = fread(buf, 1, BUFMAX, fpIn);
                if (buf_len <= 0) //read plain over
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
        memset(md5sum, 0, MD5SIZE);

        buf_len = 0;
        memset(buf, 0, BUFMAX);
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

        //Open the file to save plain
        fpOut = fopen(file_path, "wb");

        if (fpOut == NULL)
        {
                free(buf);
                return -301;
        }

        //Cycle read cipher, decrypt and save to plain file
        while (1)
        {
                buf_len = 0;
                memset(buf, 0, BUFMAX);
                buf_len = server_sc_recv(new_fd, buf, BUFMAX, us_sk, us_sk_length);
                if (buf_len < 0)
                {
                        free(buf);
                        return buf_len;
                }
                if (strcmp(buf, "filend") == 0)
                        break;
                fwrite(buf, 1, buf_len, fpOut); //save plain to file
        }

        fclose(fpOut);

        char md5sum[MD5SIZE];
        memset(md5sum, 0, MD5SIZE);

        buf_len = 0;
        memset(buf, 0, BUFMAX);
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
                return -102;
        }

        free(buf);

        return 0;
}
