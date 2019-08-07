#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include "client_ctrl.h"

int client_auth(int sockfd, char *user_id, char *user_pw, char *bio_key, int bio_key_length, char *us_sk)
{
        /* Define variables */
        BN_CTX *ctx = NULL;

        EC_builtin_curve *curves = NULL;
        EC_GROUP *group = NULL;

        EC_POINT *pubkey = NULL;
        EC_POINT *Ta = NULL;
        EC_POINT *asP = NULL;
        EC_POINT *Tb = NULL;
        EC_POINT *abP = NULL;

        BIGNUM *p = NULL;
        BIGNUM *rnd_a = NULL;

        size_t hash_in_len = 0;
        size_t asP_buf_len = 0;
        size_t Ta_buf_len = 0;
        size_t Tb_buf_len = 0;
        size_t rnd_rs_buf_len = 0;
        size_t s_Auth_len = 0;
        size_t hmac_in_len = 0;
        size_t s_u_Auth_len = 0;
        size_t abP_buf_len = 0;
        size_t p_len = 0;
        size_t pubkey_len = 0;

        int crv_len = 0;
        int nid = 0;
        int result = MD5SIZE;
        int ret = 0;
        int i = 0;

        char fun[FUN_MAX_LENGTH] = "auth";
        char replay[RE_MAX_LENGTH] = {0};
        char err_res[32] = {0};

        char *hash_in = NULL;
        char *asP_buf = NULL;
        char *Ta_buf = NULL;
        char *p_buf = NULL;
        char *pubkey_buf = NULL;
        char *s_ID = NULL;
        char *Tb_buf = NULL;
        char *rnd_rs_buf = NULL;
        char *s_Auth = NULL;
        char *K = NULL;
        char *w_auth = NULL;
        char *u_Auth = NULL;
        char *hmac_in = NULL;
        char *s_u_Auth = NULL;
        char *abP_buf = NULL;
        char *u_n = NULL;

        /* Auth start */
        printf("client_auth start!\n");
        ret = client_socket_send(sockfd, fun, strlen(fun));
        if (ret < 0)
                return ret;

        ctx = BN_CTX_new();

        /* Get server's big prime number p, and public key pubkey */
        p_buf = (char *)malloc(BUFMAX * sizeof(char));
        pubkey_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(p_buf, 0, BUFMAX);
        p_len = client_socket_recv(sockfd, p_buf, BUFMAX);
        if (p_len < 0)
        {
                printf("p recv err\n");
                result = p_len;
                goto end;
        }
        printf("p recv suc\n");

        memset(pubkey_buf, 0, BUFMAX);
        pubkey_len = client_socket_recv(sockfd, pubkey_buf, BUFMAX);
        if (pubkey_len < 0)
        {
                printf("pubkey recv err\n");
                result = pubkey_len;
                goto end;
        }
        printf("pubkey recv suc\n");

        p = BN_new();
        p = BN_bin2bn((unsigned char *)p_buf, p_len, p);
        if (p == NULL)
        {
                printf("p BN_bin2bn err\n");
                result = -602;
                goto end;
        }
        printf("p BN_bin2bn suc\n");

        /* Initialize EC */
        /* Get the number of EC */
        crv_len = EC_get_builtin_curves(NULL, 0);
        curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) *crv_len);

        /* Get the list of ECC */
        EC_get_builtin_curves(curves, crv_len);

        /* Choose one EC */
        nid = curves[19].nid;

        /* Generate the EC */
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL)
        {
                printf("EC_GROUP_new_by_curve_name err!\n");
                result = -601;
                goto end;
        }
        printf("EC_GROUP_new_by_curve_name suc!\n");

        /* Get the public key */
        pubkey = EC_POINT_new(group);
        ret = EC_POINT_oct2point(group, pubkey, (unsigned char *)pubkey_buf, pubkey_len, ctx);
        if (ret == 0)
        {
                client_err_msg();
                printf("pubkey EC_POINT_oct2point err\n");
                result = -601;
                goto end;
        }
        printf("pubkey EC_POINT_oct2point suc\n");

        /* Generate random number a */
        rnd_a = BN_new();
        ret = BN_rand_range(rnd_a, p);
        if (ret != 1)
        {
                printf("rnd_a BN_rand_range err\n");
                result = -602;
                goto end;
        }
        printf("rnd_a BN_rand_range suc\n");

        /* Calculate Ta = aP */
        if ((Ta = EC_POINT_new(group)) == NULL)
        {
                printf("Ta EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("Ta EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, Ta, rnd_a, NULL, NULL, ctx);
        if (ret != 1)
        {
                printf("Ta, EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("Ta EC_POINT_mul suc\n");

        /* Calculate a*sP */
        if ((asP = EC_POINT_new(group)) == NULL)
        {
                printf("asP EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("asP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, asP, NULL, pubkey, rnd_a, ctx);
        if (ret != 1)
        {
                printf("asP EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("asP EC_POINT_mul suc\n");

        /* Calculate K = H(a*sP||Ta||sP) */
        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        asP_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(asP_buf, 0, BUFMAX);
        asP_buf_len = EC_POINT_point2oct(group, asP, POINT_CONVERSION_COMPRESSED, (unsigned char *)asP_buf, BUFMAX, ctx);
        if (asP_buf_len == 0)
        {
                printf("asP EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("asP EC_POINT_point2oct suc\n");

        Ta_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(Ta_buf, 0, BUFMAX);
        Ta_buf_len = EC_POINT_point2oct(group, Ta, POINT_CONVERSION_COMPRESSED, (unsigned char *)Ta_buf, BUFMAX, ctx);
        if (Ta_buf_len == 0)
        {
                printf("Ta EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("Ta EC_POINT_point2oct suc\n");

        memset(hash_in, 0, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, asP_buf, &hash_in_len, asP_buf_len);
        client_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        client_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        K = (char *)malloc(HASHSIZE * sizeof(char));
        memset(K, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)K);

        /* Calculate w_auth = H(bio_key||user_pw) */
        memset(hash_in, 0, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, bio_key, &hash_in_len, bio_key_length);
        client_memcat(hash_in, user_pw, &hash_in_len, strlen(user_pw));

        w_auth = (char *)malloc(HASHSIZE * sizeof(char));
        memset(w_auth, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)w_auth);

        /* Calculate u_Auth = H(K||w_auth) */
        memset(hash_in, 0, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        u_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        memset(u_Auth, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_Auth);

        /* Send user_id, Ta, u_Auth to server */
        ret = client_socket_send(sockfd, user_id, strlen(user_id));
        if (ret < 0)
        {
                printf("user_id send err\n");
                result = ret;
                goto end;
        }
        printf("user_id send suc\n");

        ret = client_socket_send(sockfd, Ta_buf, Ta_buf_len);
        if (ret < 0)
        {
                printf("Ta_buf send err\n");
                result = ret;
                goto end;
        }
        printf("Ta_buf send suc\n");

        ret = client_socket_send(sockfd, u_Auth, HASHSIZE);
        if (ret < 0)
        {
                printf("u_Auth send err\n");
                rresult = ret;
                goto end;
        }
        printf("u_Auth send suc\n");

        /* Get s_ID, Tb, rnd_rs, s_Auth from server */
        s_ID = (char *)malloc(BUFMAX * sizeof(char));
        Tb_buf = (char *)malloc(BUFMAX * sizeof(char));
        rnd_rs_buf = (char *)malloc(BUFMAX * sizeof(char));
        s_Auth = (char *)malloc(HMACSIZE * sizeof(char));

        memset(s_ID, 0, BUFMAX);
        ret = client_socket_recv(sockfd, s_ID, BUFMAX);
        if (ret < 0)
        {
                printf("s_ID recv err\n");
                result = ret;
                goto end;
        }
        printf("s_ID recv suc\n");

        memset(Tb_buf, 0, BUFMAX);
        Tb_buf_len = client_socket_recv(sockfd, Tb_buf, BUFMAX);
        if (Tb_buf_len < 0)
        {
                printf("Tb recv err\n");
                result = Tb_buf_len;
                goto end;
        }
        printf("Tb recv suc\n");

        if ((Tb = EC_POINT_new(group)) == NULL)
        {
                printf("Tb EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("Tb EC_POINT_new suc\n");

        ret = EC_POINT_oct2point(group, Tb, (unsigned char *)Tb_buf, Tb_buf_len, ctx);
        if (ret == 0)
        {
                printf("Tb EC_POINT_oct2point err\n");
                result = -601;
                goto end;
        }
        printf("Tb EC_POINT_oct2point suc\n");

        memset(rnd_rs_buf, 0, BUFMAX);
        rnd_rs_buf_len = client_socket_recv(sockfd, rnd_rs_buf, BUFMAX);
        if (rnd_rs_buf_len < 0)
        {
                printf("rnd_rs recv err\n");
                result = rnd_rs_buf_len;
                goto end;
        }
        printf("rnd_rs recv suc\n");

        memset(s_Auth, 0, HMACSIZE);
        s_Auth_len = client_socket_recv(sockfd, s_Auth, HMACSIZE);
        if (s_Auth_len < 0)
        {
                printf("s_Auth recv err\n");
                result = s_Auth_len;
                goto end;
        }
        printf("s_Auth recv suc\n");

        /* Auth s_Auth = HMACk(Ta||Tb||pubkey||rnd_rs */
        hmac_in = (char *)malloc(3 * BUFMAX * sizeof(char));
        memset(hmac_in, 0, 3*BUFMAX);
        hmac_in_len = 0;
        client_memcat(hmac_in, Ta_buf, &hmac_in_len, Ta_buf_len);
        client_memcat(hmac_in, Tb_buf, &hmac_in_len, Tb_buf_len);
        client_memcat(hmac_in, pubkey_buf, &hmac_in_len, pubkey_len);
        client_memcat(hmac_in, rnd_rs_buf, &hmac_in_len, rnd_rs_buf_len);

        s_u_Auth = (char *)malloc(HMACSIZE * sizeof(char));
        memset(s_u_Auth, 0, HMACSIZE);
        s_u_Auth_len = 0;
        HMAC(EVP_sha1(), K, HASHSIZE, (unsigned char *)hmac_in, hmac_in_len, (unsigned char *)s_u_Auth, (unsigned int *)&s_u_Auth_len);

        ret = client_check(s_Auth, s_u_Auth, s_Auth_len, s_u_Auth_len);
        if (ret != 0)
        {
                printf("s_Auth auth err!\n");
                result = -1;
                goto end;
        }
        printf("s_Auth auth suc!\n");

        /* Calculate abP = a*Tb */
        if ((abP = EC_POINT_new(group)) == NULL)
        {
                printf("abP EC_POINT_new err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, abP, NULL, Tb, rnd_a, ctx);
        if (ret != 1)
        {
                printf("abP EC_POINT_mul err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_mul suc\n");

        /* Calculate us_sk = H(K||w_auth||abP||user_id||s_ID||Ta||Tb||sP) */
        memset(hash_in, 0, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        abP_buf = (char *)malloc(BUFMAX * sizeof(char));
        memset(asP_buf, 0, BUFMAX);
        abP_buf_len = EC_POINT_point2oct(group, abP, POINT_CONVERSION_COMPRESSED, (unsigned char *)abP_buf, BUFMAX, ctx);
        if (abP_buf_len == 0)
        {
                printf("abP EC_POINT_point2oct err\n");
                result = -601;
                goto end;
        }
        printf("abP EC_POINT_point2oct suc\n");

        client_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        client_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        client_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));
        client_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        client_memcat(hash_in, Tb_buf, &hash_in_len, Tb_buf_len);
        client_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        memset(us_sk, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)us_sk);

        /* Calculate u_n = H(K||w_auth||abP||user_id||s_ID) */
        memset(hash_in, 0, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        client_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        client_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));

        u_n = (char *)malloc(HASHSIZE * sizeof(char));
        memset(u_n, 0, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_n);

        /* Send u_n to server */
        ret = client_socket_send(sockfd, u_n, HASHSIZE);
        if (ret < 0)
        {
                printf("u_n send err\n");
                result = ret;
                goto end;
        }
        printf("u_n send suc\n");

        memset(replay, 0, RE_MAX_LENGTH);
        ret = client_socket_recv(sockfd, replay, RE_MAX_LENGTH);
        if (ret < 0)
        {
                printf("replay recv err\n");
                result = ret;
                goto end;
        }
        else if (strcmp(replay, "auth_OK") != 0)
        {
                printf("auth failed\n");
                result = -1;
                goto end;
        }

        /* Free the memory*/
end:
        if (ctx != NULL)
        {
                BN_CTX_free(ctx);
        }

        if (group != NULL)
        {
                EC_GROUP_free(group);
        }

        if (p != NULL)
        {
                BN_free(p);
        }

        if (rnd_a != NULL)
        {
                BN_free(rnd_a);
        }

        if (pubkey != NULL)
        {
                EC_POINT_free(pubkey);
        }

        if (Ta != NULL)
        {
                EC_POINT_free(Ta);
        }

        if (asP != NULL)
        {
                EC_POINT_free(asP);
        }

        if (Tb != NULL)
        {
                EC_POINT_free(Tb);
        }

        if (abP != NULL)
        {
                EC_POINT_free(abP);
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

        if (curves != NULL)
        {
                free(curves);
                curves = NULL;
        }

        if (hash_in != NULL)
        {
                free(hash_in);
                hash_in = NULL;
        }

        if (asP_buf != NULL)
        {
                free(asP_buf);
                asP_buf = NULL;
        }

        if (Ta_buf != NULL)
        {
                free(Ta_buf);
                Ta_buf = NULL;
        }

        if (K != NULL)
        {
                free(K);
                K = NULL;
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

        if (s_ID != NULL)
        {
                free(s_ID);
                s_ID = NULL;
        }

        if (Tb_buf != NULL)
        {
                free(Tb_buf);
                Tb_buf = NULL;
        }

        if (rnd_rs_buf != NULL)
        {
                free(rnd_rs_buf);
                rnd_rs_buf = NULL;
        }

        if (s_Auth != NULL)
        {
                free(s_Auth);
                s_Auth = NULL;
        }

        if (hmac_in != NULL)
        {
                free(hmac_in);
                hmac_in = NULL;
        }

        if (s_u_Auth != NULL)
        {
                free(s_u_Auth);
                s_u_Auth = NULL;
        }

        if (abP_buf != NULL)
        {
                free(abP_buf);
                abP_buf = NULL;
        }

        if (u_n != NULL)
        {
                free(u_n);
                u_n = NULL;
        }

        printf("client_auth finished!\n");

        return result;
}
