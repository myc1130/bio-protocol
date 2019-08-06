#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include "client_ctrl.h"

#define AES_BLOCK_NUM 64

int file_encrypt(char *src_file_path, char *dst_file_path, char *key, int key_length)
{
								char iv[EVP_MAX_KEY_LENGTH]; //保存初始化向量的数组
								EVP_CIPHER_CTX ctx;     //EVP加密上下文环境
								char out[AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE]; //保存解密后明文的缓冲区数组
								int outl;
								char in[AES_BLOCK_NUM * AES_BLOCK_SIZE];         //保存密文数据的数组
								int inl;
								int ret;
								int i;
								FILE *fpIn;
								FILE *fpOut;

								//打开待加密文件
								fpIn = fopen(src_file_path, "rb");
								if(fpIn==NULL)
								{
																return -301;//file open err
								}
								//打开保存密文的文件
								fpOut = fopen(dst_file_path, "wb");
								if(fpOut==NULL)
								{
																fclose(fpIn);//file open err
																return -301;
								}

								//设置iv
								bzero(iv, EVP_MAX_IV_LENGTH);
								for(i = 0; i < EVP_MAX_IV_LENGTH; i++)
								{
																iv[i] = i;
								}

								//初始化ctx
								EVP_CIPHER_CTX_init(&ctx);

								if (key_length == 16)
								{
																ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
								}
								else if (key_length == 24)
								{
																ret = EVP_EncryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
								}
								else if (key_length == 32)
								{
																ret = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv);
								}
								else
								{
																return -401;//key_length err
								}

								if(ret != 1)
								{
																EVP_CIPHER_CTX_cleanup(&ctx);
																return -402;
								}

								bzero(in, AES_BLOCK_NUM * AES_BLOCK_SIZE);
								bzero(out, AES_BLOCK_NUM * AES_BLOCK_SIZE + AES_BLOCK_SIZE);

								while(1)
								{
																inl = fread(in, 1, 64 * AES_BLOCK_SIZE, fpIn);
																if(inl <= 0) //读取原文结束
																								break;
																ret = EVP_EncryptUpdate(&ctx, (unsigned char *)out, &outl, (unsigned char *)in, inl);//加密
																if(ret != 1)
																{
																								fclose(fpIn);
																								fclose(fpOut);
																								EVP_CIPHER_CTX_cleanup(&ctx);
																								return -402;
																}
																fwrite(out, 1, outl, fpOut);//保存密文到文件
								}
								//加密结束
								ret = EVP_EncryptFinal_ex(&ctx, (unsigned char *)out, &outl);
								if(ret != 1)
								{
																fclose(fpIn);
																fclose(fpOut);
																EVP_CIPHER_CTX_cleanup(&ctx);
																return -402;
								}
								fwrite(out, 1, outl, fpOut);
								fclose(fpIn);
								fclose(fpOut);

								EVP_CIPHER_CTX_cleanup(&ctx);     //清除EVP加密上下文环境

								printf("Encryption finished\n");
								return 0;
}
