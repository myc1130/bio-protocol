#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include "server_ctrl.h"

int server_auth(int new_fd, MYSQL mysql, char *us_sk)
{
        BN_CTX *ctx = NULL;

        EC_builtin_curve *curves = NULL;
        EC_KEY *key = NULL;
        EC_GROUP *group = NULL;

        EC_POINT *pubkey = NULL;
        EC_POINT *Ta = NULL;
        EC_POINT *privkeyTa = NULL;
        EC_POINT *Tb = NULL;
        EC_POINT *abP = NULL;

        BIGNUM *p = NULL;
        BIGNUM *a = NULL;
        BIGNUM *b = NULL;
        BIGNUM *privkey = NULL;
        BIGNUM *rnd_b = NULL;
        BIGNUM *rnd_rs = NULL;

        size_t hmac_in_len = 0;
        size_t p_len = 0;
        size_t pubkey_len = 0;
        size_t Ta_buf_len = 0;
        size_t u_Auth_len = 0;
        size_t hash_in_len = 0;
        size_t privkeyTa_buf_len = 0;
        size_t Tb_buf_len = 0;
        size_t rnd_rs_buf_len = 0;
        size_t s_Auth_len = 0;
        size_t abP_buf_len = 0;
        size_t u_n_len = 0;

        int crv_len = 0;
        int nid = 0;
        int i = 0;
        int ret = 0;
        int result = MD5SIZE;

        char err_res[32] = {0};
        char replay[RE_MAX_LENGTH] = {0};

        char *hmac_in = NULL;
        char *p_buf = NULL;
        char *pubkey_buf = NULL;
        char *user_id = NULL;
        char *Ta_buf = NULL;
        char *u_Auth = NULL;
        char *w_auth = NULL;
        char *K = NULL;
        char *hash_in = NULL;
        char *u_s_Auth = NULL;
        char *privkeyTa_buf = NULL;
        char *Tb_buf = NULL;
        char *rnd_rs_buf = NULL;
        char *s_Auth = NULL;
        char *s_ID = NULL;
        char *abP_buf = NULL;
        char *u_n = NULL;
        char *s_n = NULL;

        /* Auth start */
        printf("server_auth start!\n");
        ctx = BN_CTX_new();

        /* Initilate EC */
        key = EC_KEY_new();
        if (key == NULL)
        {
                printf("EC_KEY_new err\n");
                result = -601;
                goto end;
        }
        printf("EC_KEY_new suc\n");

        /* Get the number of EC */
        crv_len = EC_get_builtin_curves(NULL, 0);
        curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);

        /* Get the list of EC */
        EC_get_builtin_curves(curves, crv_len);

        /* Choose one EC */
        nid = curves[2].nid;

        /* Generate the EC */
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL)
        {
                printf("EC_GROUP_new_by_curve_name err\n");
                result = -601;
                goto end;
        }
        printf("EC_GROUP_new_by_curve_name suc\n");

        /* Set the parameters of key */
        ret = EC_KEY_set_group(key, group);
        if (ret != 1)
        {
                printf("EC_KEY_set_group err\n");
                result = -601;
                goto end;
        }
        printf("EC_KEY_set_group suc\n");

        /* Generate the key */
        ret = EC_KEY_generate_key(key);
        if (ret != 1)
        {
                printf("EC_KEY_generate_key err\n");
                result = -601;
                goto end;
        }
        printf("EC_KEY_generate_key suc\n");

        /* Check the key */
        ret = EC_KEY_check_key(key);
        if (ret != 1)
        {
                printf("EC_KEY_check_key err\n");
                result = -601;
                goto end;
        }
        printf("EC_KEY_check_key suc\n");

        ret = EC_GROUP_check(group, ctx);
        if (ret == 0)
        {
                printf("group is not valid\n");
                result = -601;
                goto end;
        }
        printf("group is valid\n");

        p = BN_new();
        a = BN_new();
        b = BN_new();
        ret = EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
        if (ret == 0)
        {
                printf("EC_GROUP_get_curve_GFp err\n");
                result = -601;
                goto end;
        }
        printf("EC_GROUP_get_curve_GFp suc\n");

        pubkey = (EC_POINT *)EC_KEY_get0_public_key(key);
        privkey = (BIGNUM *)EC_KEY_get0_private_key(key);

        printf("ec init finished\n");

        /* Send the big prime p, public key pubkey */
        p_len = BN_num_bits(p);
        p_buf = (char *)malloc(BUFMAX * sizeof(char));

        pubkey_buf = (char *)malloc(BUFMAX * sizeof(char));

        memset(p_buf, 0, BUFMAX);
        p_len = BN_bn2bin(p, (unsigned char *)p_buf);
        if (p_len == 0)
        {
                printf("p BN_bn2bin err\n");
                result = -602;
                goto end;
        }
        printf("p BN_bn2bin suc\n");

        memset(pubkey_buf, 0, BUFMAX);
        pubkey_len = EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_COMPRESSED, (unsigned char *)pubkey_buf, BUFMAX, ctx);
        if (pubkey_len == 0)
        {
                printf("pubkey EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("pubkey EC_POINT_point2oct suc\n");

        ret = server_socket_send(new_fd, p_buf, p_len);
        if (ret < 0)
        {
                printf("p send err\n");
                result = ret;
                goto end;
        }
        printf("p send suc\n");

        ret = server_socket_send(new_fd, pubkey_buf, pubkey_len);
        if (ret < 0)
        {
                printf("pubkey send err\n");
                result = ret;
                goto end;
        }
        printf("pubkey send suc\n");

        /* Receive the user_id, Ta, u_Auth */
        user_id = (char *)malloc(BUFMAX * sizeof(char));
        Ta_buf = (char *)malloc(BUFMAX * sizeof(char));
        Ta_buf_len = 0;

        u_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        u_Auth_len = 0;

        memset(user_id, 0, BUFMAX);
        ret = server_socket_recv(new_fd, user_id, BUFMAX);
        if (ret < 0)
        {
                printf("user_id recv err\n");
                result = ret;
                goto end;
        }

        printf("user_id recv suc\n");

        memset(Ta_buf, 0, BUFMAX);
        Ta_buf_len = server_socket_recv(new_fd, Ta_buf, BUFMAX);
        if (Ta_buf_len < 0)
        {
                printf("Ta recv err\n");
                result = Ta_buf_len;
                goto end;
        }

        printf("Ta recv suc\n");

        if ((Ta = EC_POINT_new(group)) == NULL)
        {
                printf("Ta EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("Ta EC_POINT_new suc\n");

        ret = EC_POINT_oct2point(group, Ta, (unsigned char *)Ta_buf, Ta_buf_len, ctx);
        if (ret == 0)
        {
                printf("Ta EC_POINT_oct2point err\n");
                result = -601;
                goto end;
        }
        printf("Ta EC_POINT_oct2point suc\n");

        memset(u_Auth, 0, HASHSIZE);
        u_Auth_len = server_socket_recv(new_fd, u_Auth, HASHSIZE);
        if (u_Auth_len < 0)
        {
                printf("u_Auth recv err\n");
                result = u_Auth_len;
                goto end;
        }
        printf("u_Auth recv suc\n");

        /* Search the database to get w_auth according to the user_id */
        w_auth = (char *)malloc(HASHSIZE * sizeof(char));

        memset(w_auth, 0, HASHSIZE);
        ret = server_mysql_getwauth(mysql, user_id, w_auth);
        if (ret < 0)
        {
                printf("server_mysql_getwauth err\n");
                result = ret;
                goto end;
        }
        printf("server_mysql_getwauth suc\n");

        /* Calculate K = H(s*Ta||Ta||sP) */
        if ((privkeyTa = EC_POINT_new(group)) == NULL)
        {
                printf("privkeyTa EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("privkeyTa EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, privkeyTa, NULL, Ta, privkey, ctx);
        if (ret != 1)
        {
                printf("privkeyTa EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("privkeyTa EC_POINT_mul suc\n");

        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        privkeyTa_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(privkeyTa_buf, 0, BUFMAX);
        privkeyTa_buf_len = EC_POINT_point2oct(group, privkeyTa, POINT_CONVERSION_COMPRESSED, (unsigned char *)privkeyTa_buf, BUFMAX, ctx);
        if (privkeyTa_buf_len == 0)
        {
                printf("privkeyTa EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("privkeyTa EC_POINT_point2oct suc\n");

        memset(hash_in, 0, 3 * BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, privkeyTa_buf, &hash_in_len, privkeyTa_buf_len);
        server_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        server_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        K = (char *)malloc(HASHSIZE * sizeof(char));
        memset(K, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)K);

        /* Auth u_Auth = H(K||w_auth) */
        memset(hash_in, 0, 3 * BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        u_s_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        memset(u_s_Auth, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_s_Auth);

        ret = server_check(u_Auth, u_s_Auth, u_Auth_len, HASHSIZE);
        if (ret != 0)
        {
                printf("u_Auth auth err!\n");
                result = -1;
                goto end;
        }
        printf("u_Auth auth suc!\n");

        /* Generate random number b */
        rnd_b = BN_new();
        ret = BN_rand_range(rnd_b, p);
        if (ret != 1)
        {
                printf("rnd_b BN_rand_range err\n");
                result = -602;
                goto end;
        }
        printf("rnd_b BN_rand_range suc\n");

        /* Generate random number rs */
        rnd_rs = BN_new();
        ret = BN_rand_range(rnd_rs, p);
        if (ret != 1)
        {
                printf("rnd_rs BN_rand_range err\n");
                result = -602;
                goto end;
        }
        printf("rnd_rs BN_rand_range suc\n");

        /* Calculate Tb = bP */
        if ((Tb = EC_POINT_new(group)) == NULL)
        {
                printf("Tb EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("Tb EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, Tb, rnd_b, NULL, NULL, ctx);
        if (ret != 1)
        {
                printf("Tb EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("Tb EC_POINT_mul suc\n");

        /* Calculate s_Auth = HMACk(Ta||Tb||pubkey||rnd_rs)*/

        hmac_in = (char *)malloc(3 * BUFMAX * sizeof(char));
        memset(hmac_in, 0, 3 * BUFMAX);
        hmac_in_len = 0;
        server_memcat(hmac_in, Ta_buf, &hmac_in_len, Ta_buf_len);

        Tb_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(Tb_buf, 0, BUFMAX);
        Tb_buf_len = EC_POINT_point2oct(group, Tb, POINT_CONVERSION_COMPRESSED, (unsigned char *)Tb_buf, BUFMAX, ctx);
        if (Tb_buf_len == 0)
        {
                printf("Tb EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("Tb EC_POINT_point2oct suc\n");

        server_memcat(hmac_in, Tb_buf, &hmac_in_len, Tb_buf_len);
        server_memcat(hmac_in, pubkey_buf, &hmac_in_len, pubkey_len);

        rnd_rs_buf_len = BN_num_bytes(rnd_rs);
        rnd_rs_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(rnd_rs_buf, 0, BUFMAX);
        rnd_rs_buf_len = BN_bn2bin(rnd_rs, (unsigned char *)rnd_rs_buf);
        server_memcat(hmac_in, rnd_rs_buf, &hmac_in_len, rnd_rs_buf_len);

        s_Auth = (char *)malloc(HMACSIZE * sizeof(char));
        memset(s_Auth, 0, HMACSIZE);
        s_Auth_len = 0;
        HMAC(EVP_sha1(), K, HASHSIZE, (unsigned char *)hmac_in, hmac_in_len, (unsigned char *)s_Auth, (unsigned int *)&s_Auth_len);

        /* Calculate abP = b*Ta */
        if ((abP = EC_POINT_new(group)) == NULL)
        {
                printf("abP EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, abP, NULL, Ta, rnd_b, ctx);
        if (ret != 1)
        {
                printf("abP EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_mul suc\n");

        /* Get s_ID*/
        s_ID = (char *)malloc(BUFMAX * sizeof(char));
        memset(s_ID, 0, BUFMAX);
        strcpy(s_ID, "mychost");

        /* Calculate us_sk = H(K||w_auth||abP||user_id||s_ID||Ta||Tb||sP) */
        memset(hash_in, 0, 3 * BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        abP_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(abP_buf, 0, BUFMAX);
        abP_buf_len = EC_POINT_point2oct(group, abP, POINT_CONVERSION_COMPRESSED, (unsigned char *)abP_buf, BUFMAX, ctx);
        if (abP_buf_len == 0)
        {
                printf("abP EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_point2oct suc\n");

        server_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        server_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        server_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));
        server_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        server_memcat(hash_in, Tb_buf, &hash_in_len, Tb_buf_len);
        server_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        memset(us_sk, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)us_sk);

        /* Send s_ID, Tb, rnd_rs, s_Auth */
        ret = server_socket_send(new_fd, s_ID, strlen(s_ID));
        if (ret < 0)
        {
                printf("s_ID send err\n");
                result = ret;
                goto end;
        }
        printf("s_ID send suc\n");

        ret = server_socket_send(new_fd, Tb_buf, Tb_buf_len);
        if (ret < 0)
        {
                printf("Tb send err\n");
                result = ret;
                goto end;
        }
        printf("Tb send suc\n");

        ret = server_socket_send(new_fd, rnd_rs_buf, rnd_rs_buf_len);
        if (ret < 0)
        {
                printf("rnd_rs send err\n");
                result = ret;
                goto end;
        }
        printf("rnd_rs send suc\n");

        ret = server_socket_send(new_fd, s_Auth, s_Auth_len);
        if (ret < 0)
        {
                printf("s_Auth send err\n");
                result = ret;
                goto end;
        }
        printf("s_Auth send suc\n");

        /* Receive u_n */
        u_n = (char *)malloc(HASHSIZE * sizeof(char));
        memset(u_n, 0, HASHSIZE);
        u_n_len = server_socket_recv(new_fd, u_n, HASHSIZE);
        if (u_n_len < 0)
        {
                printf("u_n recv err\n");
                result = u_n_len;
                goto end;
        }
        printf("u_n recv suc\n");

        /* Auth u_n = H(K||w_auth||abP||user_id||s_ID) */
        memset(hash_in, 0, 3 * BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        server_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        server_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));

        s_n = (char *)malloc(HASHSIZE * sizeof(char));
        memset(s_n, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)s_n);
        ret = server_check(u_n, s_n, u_n_len, HASHSIZE);
        if (ret != 0)
        {
                printf("u_n auth err\n");
                result = -1;
                goto end;
        }
        printf("u_n auth suc\n");

        memset(replay, 0, RE_MAX_LENGTH);
        strcpy(replay, "auth_OK");
        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
        {
                printf("replay recv err\n");
                result = ret;
                goto end;
        }

end:
        if (ctx != NULL)
        {
                BN_CTX_free(ctx);
        }

        if (key != NULL)
        {
                EC_KEY_free(key);
        }

        if (group != NULL)
        {
                EC_GROUP_free(group);
        }

        if (p != NULL)
        {
                BN_free(p);
        }

        if (a != NULL)
        {
                BN_free(a);
        }

        if (b != NULL)
        {
                BN_free(b);
        }

        if (rnd_b != NULL)
        {
                BN_free(rnd_b);
        }

        if (rnd_rs != NULL)
        {
                BN_free(rnd_rs);
        }

        if (Ta != NULL)
        {
                EC_POINT_free(Ta);
        }

        if (Tb != NULL)
        {
                EC_POINT_free(Tb);
        }

        if (abP != NULL)
        {
                EC_POINT_free(abP);
        }

        if (privkeyTa != NULL)
        {
                EC_POINT_free(privkeyTa);
        }

        if (curves != NULL)
        {
                free(curves);
                curves = NULL;
        }

        if (p_buf != NULL)
        {
                free(p_buf);
                p_buf = NULL;
        }

        if (pubkey_buf != NULL)
        {
                free(pubkey_buf);
                pubkey_buf = NULL;
        }

        if (Ta_buf != NULL)
        {
                free(Ta_buf);
                Ta_buf = NULL;
        }

        if (Tb_buf != NULL)
        {
                free(Tb_buf);
                Tb_buf = NULL;
        }

        if (privkeyTa_buf != NULL)
        {
                free(privkeyTa_buf);
                privkeyTa_buf = NULL;
        }

        if (rnd_rs_buf != NULL)
        {
                free(rnd_rs_buf);
                rnd_rs_buf = NULL;
        }

        if (abP_buf != NULL)
        {
                free(abP_buf);
                abP_buf = NULL;
        }

        if (hash_in != NULL)
        {
                free(hash_in);
                hash_in = NULL;
        }

        if (hmac_in != NULL)
        {
                free(hmac_in);
                hmac_in = NULL;
        }

        if (K != NULL)
        {
                free(K);
                K = NULL;
        }

        if (user_id != NULL)
        {
                free(user_id);
                user_id = NULL;
        }

        if (w_auth != NULL)
        {
                free(w_auth);
                w_auth = NULL;
        }

        if (u_Auth != NULL)
        {
                free(u_Auth);
                u_Auth = NULL;
        }

        if (u_s_Auth != NULL)
        {
                free(u_s_Auth);
                u_s_Auth = NULL;
        }

        if (u_n != NULL)
        {
                free(u_n);
                u_n = NULL;
        }

        if (s_n != NULL)
        {
                free(s_n);
                s_n = NULL;
        }

        if (s_Auth != NULL)
        {
                free(s_Auth);
                s_Auth = NULL;
        }

        if (s_ID != NULL)
        {
                free(s_ID);
                s_ID = NULL;
        }

        printf("server_auth finished!\n");

        return MD5SIZE;
}
