#include <openssl/md5.h>
#include "client_ctrl.h"

#define MD5SIZE 16

int client_md5sum(char *buf, int buf_len, char *md5sum)
{
        memset(md5sum, 0, MD5SIZE);
        MD5((unsigned char *)buf, buf_len, (unsigned char *)md5sum);

        return 0;
}
int client_md5check(char *buf, int buf_len, char *md5sum)
{
        char outmd[MD5SIZE];
        memset(outmd, 0, MD5SIZE);

        MD5((unsigned char *)buf, buf_len, (unsigned char *)outmd);

        if (memcmp(outmd, md5sum, MD5SIZE) != 0)
        {
                return -1;
        }

        return 0;
}
int client_md5sum_file(char *file_path, char *md5sum)
{
        MD5_CTX ctx;
        char outmd[MD5SIZE];
        char buf[BUFMAX];
        int len;
        FILE *fp = NULL;

        memset(outmd, 0, MD5SIZE);
        memset(buf, 0, BUFMAX);
        len = 0;
        fp = fopen(file_path, "rb");
        if (fp == NULL)
        {
                printf("Can't open file %s\n", file_path);
                return -301;
        }

        MD5_Init(&ctx);
        while ((len = fread(buf, 1, BUFMAX, fp)) > 0)
        {
                MD5_Update(&ctx, buf, len);
                memset(buf, 0, BUFMAX);
        }
        MD5_Final((unsigned char *)outmd, &ctx);

        memset(md5sum, 0, MD5SIZE);
        memcpy(md5sum, outmd, MD5SIZE);

        return 0;
}
int client_md5check_file(char *file_path, char *md5sum)
{
        MD5_CTX ctx;
        char outmd[MD5SIZE];
        char buf[BUFMAX];
        int len;
        FILE *fp;

        memset(outmd, 0, MD5SIZE);
        memset(buf, 0, BUFMAX);
        len = 0;
        fp = fopen(file_path, "rb");
        if (fp == NULL)
        {
                printf("Can't open file %s\n", file_path);
                return -301;
        }

        MD5_Init(&ctx);
        while ((len = fread(buf, 1, BUFMAX, fp)) > 0)
        {
                MD5_Update(&ctx, buf, len);
                memset(buf, 0, BUFMAX);
        }
        MD5_Final((unsigned char *)outmd, &ctx);

        if (memcmp(outmd, md5sum, MD5SIZE) != 0)
        {
                return -1;
        }

        return 0;
}
