#include "client_ctrl.h"

void client_memcat(char *dest, char *src, size_t *dest_len, size_t src_len)
{
        memcpy(dest + *dest_len, src, src_len);
        *dest_len += src_len;
}

void client_output(char *src, size_t src_len)
{
        unsigned char *out = (unsigned char *)src;
        int i = 0;
        for (i = 0; i < src_len; i++)
                printf("%02x", out[i]);
}

int client_check(char *a, char *b, size_t a_len, size_t b_len)
{
        if (a_len != b_len)
                return -1;

        return memcmp(a, b, a_len);
}
