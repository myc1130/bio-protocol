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
        printf("client_auth start!\n");
        int ret;

        char fun[FUN_MAX_LENGTH] = "auth";
        ret = client_socket_send(sockfd, fun, strlen(fun));
        if (ret < 0)
                return ret;

        int i;
        char err_res[32];

        BN_CTX *ctx;
        ctx = BN_CTX_new();

        EC_GROUP *group;
        BIGNUM *p;
        EC_POINT *pubkey;

        /* 获取服务器发送过来的椭圆曲线大素数p, 公钥pubkey */
        size_t p_len;
        size_t pubkey_len;

        char *p_buf = NULL;
        char *pubkey_buf = NULL;

        p_buf = (char *)malloc(BUFMAX * sizeof(char));
        pubkey_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(p_buf, BUFMAX);
        p_len = client_socket_recv(sockfd, p_buf, BUFMAX);
        if (p_len < 0)
        {
                BN_CTX_free(ctx);
                free(p_buf);
                free(pubkey_buf);
                printf("p recv err\n");
                return p_len;
        }
        printf("p recv suc\n");

        bzero(pubkey_buf, BUFMAX);
        pubkey_len = client_socket_recv(sockfd, pubkey_buf, BUFMAX);
        if (pubkey_len < 0)
        {
                BN_CTX_free(ctx);
                free(p_buf);
                free(pubkey_buf);
                printf("pubkey recv err\n");
                return pubkey_len;
        }
        printf("pubkey recv suc\n");

        p = BN_new();
        p = BN_bin2bn((unsigned char *)p_buf, p_len, p);
        if (p == NULL)
        {
                BN_CTX_free(ctx);
                BN_free(p);
                free(p_buf);
                free(pubkey_buf);
                printf("p BN_bin2bn err\n");
                return -602;
        }
        printf("p BN_bin2bn suc\n");

        /* 椭圆曲线初始�?*/
        EC_builtin_curve *curves;
        int crv_len;
        int nid;

        /* 获取实现的椭圆曲线个�?*/
        crv_len = EC_get_builtin_curves(NULL, 0);
        curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) *crv_len);

        /* 获取椭圆曲线列表 */
        EC_get_builtin_curves(curves, crv_len);

        /* 选取一种椭圆曲�?*/
        nid = curves[19].nid;

        /* 生成椭圆曲线 */
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL)
        {
                BN_CTX_free(ctx);
                BN_free(p);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("EC_GROUP_new_by_curve_name err!\n");
                return -601;
        }
        printf("EC_GROUP_new_by_curve_name suc!\n");

        /* 得到公钥 */
        pubkey = EC_POINT_new(group);
        ret = EC_POINT_oct2point(group, pubkey, (unsigned char *)pubkey_buf, pubkey_len, ctx);
        if (ret == 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                EC_POINT_free(pubkey);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                client_err_msg()�?
                printf("pubkey EC_POINT_oct2point err\n");
                return -601;
        }
        printf("pubkey EC_POINT_oct2point suc\n");

        /* 生成随机数a */
        BIGNUM *rnd_a;
        rnd_a = BN_new();
        ret = BN_rand_range(rnd_a, p);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("rnd_a BN_rand_range err\n");
                return -602;
        }
        printf("rnd_a BN_rand_range suc\n");

        /* 计算Ta = aP */
        EC_POINT *Ta;
        if ((Ta = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("Ta EC_POINT_new err\n");
                return -601;
        }
        printf("Ta EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, Ta, rnd_a, NULL, NULL, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("Ta, EC_POINT_mul err\n");
                return -601;
        }
        printf("Ta EC_POINT_mul suc\n");

        /* 计算a*sP */
        EC_POINT *asP;
        if ((asP = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("asP EC_POINT_new err\n");
                return -601;
        }
        printf("asP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, asP, NULL, pubkey, rnd_a, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                printf("asP EC_POINT_mul err\n");
                return -601;
        }
        printf("asP EC_POINT_mul suc\n");

        /* 计算K = H(a*sP||Ta||sP) */
        size_t hash_in_len;
        char *hash_in;
        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        size_t asP_buf_len;
        char *asP_buf;
        asP_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(asP_buf, BUFMAX);
        asP_buf_len = EC_POINT_point2oct(group, asP, POINT_CONVERSION_COMPRESSED, (unsigned char *)asP_buf, BUFMAX, ctx);
        if (asP_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                printf("asP EC_POINT_point2oct err\n");
                return -601;
        }
        printf("asP EC_POINT_point2oct suc\n");

        size_t Ta_buf_len;
        char *Ta_buf;
        Ta_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(Ta_buf, BUFMAX);
        Ta_buf_len = EC_POINT_point2oct(group, Ta, POINT_CONVERSION_COMPRESSED, (unsigned char *)Ta_buf, BUFMAX, ctx);
        if (Ta_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                printf("Ta EC_POINT_point2oct err\n");
                return -601;
        }
        printf("Ta EC_POINT_point2oct suc\n");

        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, asP_buf, &hash_in_len, asP_buf_len);
        client_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        client_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        char *K;
        K = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(K, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)K);

        /* 计算w_auth = H(bio_key||user_pw) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, bio_key, &hash_in_len, bio_key_length);
        client_memcat(hash_in, user_pw, &hash_in_len, strlen(user_pw));

        char *w_auth;
        w_auth = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(w_auth, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)w_auth);

        /* 计算u_Auth = H(K||w_auth) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        char *u_Auth;
        u_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(u_Auth, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_Auth);

        /* 发送user_id, Ta, u_Auth给服务器 */
        ret = client_socket_send(sockfd, user_id, strlen(user_id));
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                printf("user_id send err\n");
                return ret;
        }
        printf("user_id send suc\n");

        ret = client_socket_send(sockfd, Ta_buf, Ta_buf_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                printf("Ta_buf send err\n");
                return ret;
        }
        printf("Ta_buf send suc\n");

        ret = client_socket_send(sockfd, u_Auth, HASHSIZE);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                printf("u_Auth send err\n");
                return ret;
        }
        printf("u_Auth send suc\n");

        /* 接收服务器发送过来的s_ID, Tb, rnd_rs, s_Auth */
        char *s_ID;
        s_ID = (char *)malloc(BUFMAX * sizeof(char));
        size_t Tb_buf_len;
        char *Tb_buf;
        Tb_buf = (char *)malloc(BUFMAX * sizeof(char));
        size_t rnd_rs_buf_len;
        char *rnd_rs_buf;
        rnd_rs_buf = (char *)malloc(BUFMAX * sizeof(char));
        size_t s_Auth_len;
        char *s_Auth;
        s_Auth = (char *)malloc(HMACSIZE * sizeof(char));

        bzero(s_ID, BUFMAX);
        ret = client_socket_recv(sockfd, s_ID, BUFMAX);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("s_ID recv err\n");
                return ret;
        }
        printf("s_ID recv suc\n");

        bzero(Tb_buf, BUFMAX);
        Tb_buf_len = client_socket_recv(sockfd, Tb_buf, BUFMAX);
        if (Tb_buf_len < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("Tb recv err\n");
                return Tb_buf_len;
        }
        printf("Tb recv suc\n");

        EC_POINT *Tb;
        if ((Tb = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("Tb EC_POINT_new err\n");
                return -601;
        }
        printf("Tb EC_POINT_new suc\n");

        ret = EC_POINT_oct2point(group, Tb, (unsigned char *)Tb_buf, Tb_buf_len, ctx);
        if (ret == 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("Tb EC_POINT_oct2point err\n");
                return -601;
        }
        printf("Tb EC_POINT_oct2point suc\n");

        bzero(rnd_rs_buf, BUFMAX);
        rnd_rs_buf_len = client_socket_recv(sockfd, rnd_rs_buf, BUFMAX);
        if (rnd_rs_buf_len < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("rnd_rs recv err\n");
                return rnd_rs_buf_len;
        }
        printf("rnd_rs recv suc\n");

        bzero(s_Auth, HMACSIZE);
        s_Auth_len = client_socket_recv(sockfd, s_Auth, HMACSIZE);
        if (s_Auth_len < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("s_Auth recv err\n");
                return s_Auth_len;
        }
        printf("s_Auth recv suc\n");

        /* 验证s_Auth = HMACk(Ta||Tb||pubkey||rnd_rs 是否成立*/
        char *hmac_in;
        hmac_in = (char *)malloc(3 * BUFMAX * sizeof(char));
        size_t hmac_in_len;
        bzero(hmac_in, 3*BUFMAX);
        hmac_in_len = 0;
        client_memcat(hmac_in, Ta_buf, &hmac_in_len, Ta_buf_len);
        client_memcat(hmac_in, Tb_buf, &hmac_in_len, Tb_buf_len);
        client_memcat(hmac_in, pubkey_buf, &hmac_in_len, pubkey_len);
        client_memcat(hmac_in, rnd_rs_buf, &hmac_in_len, rnd_rs_buf_len);

        char *s_u_Auth;
        size_t s_u_Auth_len;
        s_u_Auth = (char *)malloc(HMACSIZE * sizeof(char));
        bzero(s_u_Auth, HMACSIZE);
        s_u_Auth_len = 0;
        HMAC(EVP_sha1(), K, HASHSIZE, (unsigned char *)hmac_in, hmac_in_len, (unsigned char *)s_u_Auth, (unsigned int *)&s_u_Auth_len);

        ret = client_check(s_Auth, s_u_Auth, s_Auth_len, s_u_Auth_len);
        if (ret != 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(hmac_in);
                free(s_u_Auth);
                printf("s_Auth auth err!\n");
                return -1;
        }
        printf("s_Auth auth suc!\n");

        /* 计算abP = a*Tb */
        EC_POINT *abP;
        if ((abP = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(hmac_in);
                free(s_u_Auth);
                printf("abP EC_POINT_new err\n");
                return -601;
        }
        printf("abP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, abP, NULL, Tb, rnd_a, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(hmac_in);
                free(s_u_Auth);
                printf("abP EC_POINT_mul err\n");
                return -601;
        }
        printf("abP EC_POINT_mul suc\n");

        /* 计算us_sk = H(K||w_auth||abP||user_id||s_ID||Ta||Tb||sP) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        size_t abP_buf_len;
        char *abP_buf;
        abP_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(asP_buf, BUFMAX);
        abP_buf_len = EC_POINT_point2oct(group, abP, POINT_CONVERSION_COMPRESSED, (unsigned char *)abP_buf, BUFMAX, ctx);
        if (abP_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(hmac_in);
                free(s_u_Auth);
                free(abP_buf);
                printf("abP EC_POINT_point2oct err\n");
                return -601;
        }
        printf("abP EC_POINT_point2oct suc\n");

        client_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        client_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        client_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));
        client_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        client_memcat(hash_in, Tb_buf, &hash_in_len, Tb_buf_len);
        client_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        bzero(us_sk, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)us_sk);

        /* 计算u_n = H(K||w_auth||abP||user_id||s_ID) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        client_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);
        client_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        client_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        client_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));

        char *u_n;
        u_n = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(u_n, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_n);

        /* 发送u_n给服务器 */
        ret = client_socket_send(sockfd, u_n, HASHSIZE);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(rnd_a);
                EC_POINT_free(pubkey);
                EC_POINT_free(Ta);
                EC_POINT_free(asP);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(p_buf);
                free(pubkey_buf);
                free(curves);
                free(hash_in);
                free(asP_buf);
                free(Ta_buf);
                free(K);
                free(w_auth);
                free(u_Auth);
                free(s_ID);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(hmac_in);
                free(s_u_Auth);
                free(abP_buf);
                free(u_n);
                printf("u_n send err\n");
                return ret;
        }
        printf("u_n send suc\n");

        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);
        ret = client_socket_recv(sockfd, replay, RE_MAX_LENGTH);
        if (ret < 0)
        {
                printf("replay recv err\n");
                return ret;
        }
        else if (strcmp(replay, "auth_OK") != 0)
        {
                printf("auth failed\n");
                return -1;
        }

        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        BN_free(p);
        BN_free(rnd_a);
        EC_POINT_free(pubkey);
        EC_POINT_free(Ta);
        EC_POINT_free(asP);
        EC_POINT_free(Tb);
        EC_POINT_free(abP);
        free(p_buf);
        free(pubkey_buf);
        free(curves);
        free(hash_in);
        free(asP_buf);
        free(Ta_buf);
        free(K);
        free(w_auth);
        free(u_Auth);
        free(s_ID);
        free(Tb_buf);
        free(rnd_rs_buf);
        free(s_Auth);
        free(hmac_in);
        free(s_u_Auth);
        free(abP_buf);
        free(u_n);

        printf("client_auth finished!\n");

        return MD5SIZE;
}
