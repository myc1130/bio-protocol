#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include "client_ctrl.h"

#define AES_BLOCK_NUM 64

int file_encrypt(char *src_file_path, char *dst_file_path, char *key, int key_length)
{
        char iv[EVP_MAX_KEY_LENGTH];                               //the array to keep iv
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();                //EVP cipher ctx
        char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //the array to keep plain
        int outl;
        char in[AES_BLOCK_NUM * AES_BLOCK_SIZE]; //the array to keep cipher
        int inl;
        int ret;
        int i;
        FILE *fpIn;
        FILE *fpOut;

        //Open the file that save plain
        fpIn = fopen(src_file_path, "rb");
        if (fpIn == NULL)
        {
                return -301; //file open err
        }
        //Open the file to save cipher
        fpOut = fopen(dst_file_path, "wb");
        if (fpOut == NULL)
        {
                fclose(fpIn); //file open err
                return -301;
        }

        //Set iv
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        for (i = 0; i < EVP_MAX_IV_LENGTH; i++)
        {
                iv[i] = i;
        }

        //Initialize ctx
        EVP_CIPHER_CTX_init(ctx);

        if (key_length == 16)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (key_length == 24)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else if (key_length == 32)
        {
                ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
        }
        else
        {
                return -401; //key_length err
        }

        if (ret != 1)
        {
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -402;
        }

        memset(in, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE);
        memset(out, 0, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);

        while (1)
        {
                inl = fread(in, 1, 64 * AES_BLOCK_SIZE, fpIn);
                if (inl <= 0) //Read original end
                        break;
                ret = EVP_EncryptUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl); //加密
                if (ret != 1)
                {
                        fclose(fpIn);
                        fclose(fpOut);
                        EVP_CIPHER_CTX_cleanup(ctx);
                        EVP_CIPHER_CTX_free(ctx);
                        return -402;
                }
                fwrite(out, 1, outl, fpOut); //Save the cipher to file
        }
        //Encrypt end
        ret = EVP_EncryptFinal_ex(ctx, (unsigned char *)out, &outl);
        if (ret != 1)
        {
                fclose(fpIn);
                fclose(fpOut);
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                return -402;
        }
        fwrite(out, 1, outl, fpOut);
        fclose(fpIn);
        fclose(fpOut);

        EVP_CIPHER_CTX_cleanup(ctx); //clear the EVP ctx
        EVP_CIPHER_CTX_free(ctx);

        printf("Encryption finished\n");
        return 0;
}
