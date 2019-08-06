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
        printf("server_auth start!\n");

        int i;
        int ret;
        char err_res[32];

        BN_CTX *ctx;
        ctx = BN_CTX_new();

        EC_KEY *key;
        EC_GROUP *group;
        BIGNUM  *p, *a, *b;
        EC_POINT *pubkey;
        BIGNUM *privkey;

        /* 椭圆曲线初始化 */
        EC_builtin_curve *curves;
        int crv_len;
        int nid;

        key = EC_KEY_new();
        if (key == NULL)
        {
                BN_CTX_free(ctx);
                printf ("EC_KEY_new err\n");
                return -601;
        }
        printf ("EC_KEY_new suc\n");

        /* 获取实现的椭圆曲线个数 */
        crv_len = EC_get_builtin_curves(NULL, 0);
        curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) *crv_len);

        /* 获取椭圆曲线列表 */
        EC_get_builtin_curves(curves, crv_len);

        /* 选取一种椭圆曲线 */
        nid = curves[2].nid;

        /* 生成椭圆曲线 */
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                free(curves);
                printf("EC_GROUP_new_by_curve_name err\n");
                return -601;
        }
        printf("EC_GROUP_new_by_curve_name suc\n");

        /* 设置密钥参数 */
        ret = EC_KEY_set_group(key, group);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                free(curves);
                printf("EC_KEY_set_group err\n");
                return -601;
        }
        printf("EC_KEY_set_group suc\n");

        /* 生成密钥 */
        ret = EC_KEY_generate_key(key);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                free(curves);
                printf("EC_KEY_generate_key err\n");
                return -601;
        }
        printf("EC_KEY_generate_key suc\n");

        /* 检查密钥 */
        ret = EC_KEY_check_key(key);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                free(curves);
                printf("EC_KEY_check_key err\n");
                return -601;
        }
        printf("EC_KEY_check_key suc\n");

        ret = EC_GROUP_check(group, ctx);
        if (ret == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                free(curves);
                printf("group is not valid\n");
                return -601;
        }
        printf("group is valid\n");

        p = BN_new();
        a = BN_new();
        b = BN_new();
        ret = EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
        if (ret == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);
                free(curves);
                printf("EC_GROUP_get_curve_GFp err\n");
                return -601;
        }
        printf("EC_GROUP_get_curve_GFp suc\n");

        pubkey = (EC_POINT *)EC_KEY_get0_public_key(key);
        privkey = (BIGNUM *)EC_KEY_get0_private_key(key);

        printf("ec init finished\n");

        /* 发送椭圆曲线大素数p, 公钥pubkey给客户端 */
        size_t p_len;
        size_t pubkey_len;

        char *p_buf = NULL;
        char *pubkey_buf = NULL;

        p_len = BN_num_bits(p);
        p_buf = (char *)malloc(BUFMAX * sizeof(char));

        pubkey_buf = (char *)malloc(BUFMAX * sizeof(char));

        bzero(p_buf, BUFMAX);
        p_len = BN_bn2bin(p, (unsigned char *)p_buf);
        if (p_len == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                printf("p BN_bn2bin err\n");
                return -602;
        }
        printf("p BN_bn2bin suc\n");

        bzero(pubkey_buf, BUFMAX);
        pubkey_len = EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_COMPRESSED, (unsigned char *)pubkey_buf, BUFMAX, ctx);
        if (pubkey_len == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                printf("pubkey EC_POINT_point2oct err\n");
                return -601;
        }
        printf("pubkey EC_POINT_point2oct suc\n");

        ret = server_socket_send(new_fd, p_buf, p_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                printf("p send err\n");
                return ret;
        }
        printf("p send suc\n");

        ret = server_socket_send(new_fd, pubkey_buf, pubkey_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                printf("pubkey send err\n");
                return ret;
        }
        printf("pubkey send suc\n");

        /* 接收客户端发送过来的user_id、 Ta、 u_Auth */
        char *user_id;
        user_id = (char *)malloc(BUFMAX * sizeof(char));

        size_t Ta_buf_len;
        char *Ta_buf;
        Ta_buf = (char *)malloc(BUFMAX * sizeof(char));
        Ta_buf_len = 0;

        size_t u_Auth_len;
        char *u_Auth;
        u_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        u_Auth_len = 0;

        bzero(user_id, BUFMAX);
        ret = server_socket_recv(new_fd, user_id, BUFMAX);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                printf("user_id recv err\n");
                return ret;
        }

        printf("user_id recv suc\n");

        bzero(Ta_buf, BUFMAX);
        Ta_buf_len = server_socket_recv(new_fd, Ta_buf, BUFMAX);
        if (Ta_buf_len < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                printf("Ta recv err\n");
                return Ta_buf_len;
        }

        printf("Ta recv suc\n");

        EC_POINT *Ta;
        if ((Ta = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                printf("Ta EC_POINT_new err\n");
                return -601;
        }
        printf("Ta EC_POINT_new suc\n");

        ret = EC_POINT_oct2point(group, Ta, (unsigned char *)Ta_buf, Ta_buf_len, ctx);
        if (ret == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                printf("Ta EC_POINT_oct2point err\n");
                return -601;
        }
        printf("Ta EC_POINT_oct2point suc\n");

        bzero(u_Auth, HASHSIZE);
        u_Auth_len = server_socket_recv(new_fd, u_Auth, HASHSIZE);
        if (u_Auth_len < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                printf("u_Auth recv err\n");
                return u_Auth_len;
        }
        printf("u_Auth recv suc\n");

        /* 根据user_id查询数据库得到w_auth*/
        char *w_auth;
        w_auth = (char *)malloc(HASHSIZE * sizeof(char));

        bzero(w_auth, HASHSIZE);
        ret = server_mysql_getwauth(mysql, user_id, w_auth);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                printf("server_mysql_getwauth err\n");
                return ret;
        }
        printf("server_mysql_getwauth suc\n");

        /* 计算K = H(s*Ta||Ta||sP) */
        EC_POINT *privkeyTa;
        if ((privkeyTa = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                printf("privkeyTa EC_POINT_new err\n");
                return -601;
        }
        printf("privkeyTa EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, privkeyTa, NULL, Ta, privkey, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                printf("privkeyTa EC_POINT_mul err\n");
                return -601;
        }
        printf("privkeyTa EC_POINT_mul suc\n");

        size_t hash_in_len;
        char *hash_in;
        hash_in = (char *)malloc(3 * BUFMAX * sizeof(char));

        size_t privkeyTa_buf_len;
        char *privkeyTa_buf;
        privkeyTa_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(privkeyTa_buf, BUFMAX);
        privkeyTa_buf_len = EC_POINT_point2oct(group, privkeyTa, POINT_CONVERSION_COMPRESSED, (unsigned char *)privkeyTa_buf, BUFMAX, ctx);
        if (privkeyTa_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                printf("privkeyTa EC_POINT_point2oct err\n");
                return -601;
        }
        printf("privkeyTa EC_POINT_point2oct suc\n");

        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, privkeyTa_buf, &hash_in_len, privkeyTa_buf_len);
        server_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        server_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        char *K;
        K = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(K, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)K);

        /* 验证u_Auth = H(K||w_auth) 是否成立 */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        char *u_s_Auth;
        u_s_Auth = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(u_s_Auth, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)u_s_Auth);

        ret = server_check(u_Auth, u_s_Auth, u_Auth_len, HASHSIZE);
        if (ret != 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);


                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                printf("u_Auth auth err!\n");
                return -1;
        }
        printf("u_Auth auth suc!\n");

        /* 生成随机数b */
        BIGNUM *rnd_b;
        rnd_b = BN_new();
        ret = BN_rand_range(rnd_b, p);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                printf("rnd_b BN_rand_range err\n");
                return -602;
        }
        printf("rnd_b BN_rand_range suc\n");

        /* 生成随机数rs */
        BIGNUM *rnd_rs;
        rnd_rs = BN_new();
        ret = BN_rand_range(rnd_rs, p);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                printf("rnd_rs BN_rand_range err\n");
                return -602;
        }
        printf("rnd_rs BN_rand_range suc\n");

        /* 计算Tb = bP */
        EC_POINT *Tb;
        if ((Tb = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                printf("Tb EC_POINT_new err\n");
                return -601;
        }
        printf("Tb EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, Tb, rnd_b, NULL, NULL, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                printf("Tb EC_POINT_mul err\n");
                return -601;
        }
        printf("Tb EC_POINT_mul suc\n");

        /* 计算s_Auth = HMACk(Ta||Tb||pubkey||rnd_rs)*/
        char *hmac_in;
        hmac_in = (char *)malloc(3 * BUFMAX * sizeof(char));
        size_t hmac_in_len;
        bzero(hmac_in, 3*BUFMAX);
        hmac_in_len = 0;
        server_memcat(hmac_in, Ta_buf, &hmac_in_len, Ta_buf_len);

        size_t Tb_buf_len;
        char *Tb_buf;
        Tb_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(Tb_buf, BUFMAX);
        Tb_buf_len = EC_POINT_point2oct(group, Tb, POINT_CONVERSION_COMPRESSED, (unsigned char *)Tb_buf, BUFMAX, ctx);
        if (Tb_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                printf("Tb EC_POINT_point2oct err\n");
                return -601;
        }
        printf("Tb EC_POINT_point2oct suc\n");

        server_memcat(hmac_in, Tb_buf, &hmac_in_len, Tb_buf_len);
        server_memcat(hmac_in, pubkey_buf, &hmac_in_len, pubkey_len);

        char *rnd_rs_buf;
        size_t rnd_rs_buf_len;
        rnd_rs_buf_len = BN_num_bytes(rnd_rs);
        rnd_rs_buf = (char *) malloc(BUFMAX * sizeof(char));
        bzero(rnd_rs_buf, BUFMAX);
        rnd_rs_buf_len = BN_bn2bin(rnd_rs, (unsigned char *)rnd_rs_buf);
        server_memcat(hmac_in, rnd_rs_buf, &hmac_in_len, rnd_rs_buf_len);

        char *s_Auth;
        size_t s_Auth_len;
        s_Auth = (char *)malloc(HMACSIZE * sizeof(char));
        bzero(s_Auth, HMACSIZE);
        s_Auth_len = 0;
        HMAC(EVP_sha1(), K, HASHSIZE, (unsigned char *)hmac_in, hmac_in_len, (unsigned char *)s_Auth, (unsigned int *)&s_Auth_len);

        /* 计算abP = b*Ta */
        EC_POINT *abP;
        if ((abP = EC_POINT_new(group)) == NULL)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("abP EC_POINT_new err\n");
                return -601;
        }
        printf("abP EC_POINT_new suc\n");

        ret = EC_POINT_mul(group, abP, NULL, Ta, rnd_b, ctx);
        if (ret != 1)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                printf("abP EC_POINT_mul err\n");
                return -601;
        }
        printf("abP EC_POINT_mul suc\n");

        /* 获取s_ID*/
        char *s_ID;
        s_ID = (char *)malloc(BUFMAX * sizeof(char));
        bzero(s_ID, BUFMAX);
        strcpy(s_ID, "mychost");

        /* 计算us_sk = H(K||w_auth||abP||user_id||s_ID||Ta||Tb||sP) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);

        size_t abP_buf_len;
        char *abP_buf;
        abP_buf = (char *)malloc(BUFMAX * sizeof(char));
        bzero(abP_buf, BUFMAX);
        abP_buf_len = EC_POINT_point2oct(group, abP, POINT_CONVERSION_COMPRESSED, (unsigned char *)abP_buf, BUFMAX, ctx);
        if (abP_buf_len == 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                printf("abP EC_POINT_point2oct err\n");
                return -601;
        }
        printf("abP EC_POINT_point2oct suc\n");

        server_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        server_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        server_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));
        server_memcat(hash_in, Ta_buf, &hash_in_len, Ta_buf_len);
        server_memcat(hash_in, Tb_buf, &hash_in_len, Tb_buf_len);
        server_memcat(hash_in, pubkey_buf, &hash_in_len, pubkey_len);

        bzero(us_sk, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)us_sk);

        /* 发送s_ID, Tb, rnd_rs, s_Auth给客户端 */
        ret = server_socket_send(new_fd, s_ID, strlen(s_ID));
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                printf("s_ID send err\n");
                return ret;
        }
        printf("s_ID send suc\n");

        ret = server_socket_send(new_fd, Tb_buf, Tb_buf_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                printf("Tb send err\n");
                return ret;
        }
        printf("Tb send suc\n");

        ret = server_socket_send(new_fd, rnd_rs_buf, rnd_rs_buf_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                printf("rnd_rs send err\n");
                return ret;
        }
        printf("rnd_rs send suc\n");

        ret = server_socket_send(new_fd, s_Auth, s_Auth_len);
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                printf("s_Auth send err\n");
                return ret;
        }
        printf("s_Auth send suc\n");

        /* 接收客户端发送过来的u_n */
        size_t u_n_len;
        char *u_n;
        u_n = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(u_n, HASHSIZE);
        u_n_len = server_socket_recv(new_fd, u_n, HASHSIZE);
        if (u_n_len < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                free(u_n);
                printf("u_n recv err\n");
                return u_n_len;
        }
        printf("u_n recv suc\n");

        /* 验证u_n = H(K||w_auth||abP||user_id||s_ID) */
        bzero(hash_in, 3*BUFMAX);
        hash_in_len = 0;
        server_memcat(hash_in, K, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, w_auth, &hash_in_len, HASHSIZE);
        server_memcat(hash_in, abP_buf, &hash_in_len, abP_buf_len);
        server_memcat(hash_in, user_id, &hash_in_len, strlen(user_id));
        server_memcat(hash_in, s_ID, &hash_in_len, strlen(s_ID));

        char *s_n;
        s_n = (char *)malloc(HASHSIZE * sizeof(char));
        bzero(s_n, HASHSIZE);
        MD5((unsigned char *)hash_in, hash_in_len, (unsigned char *)s_n);
        ret = server_check(u_n, s_n, u_n_len, HASHSIZE);
        if (ret != 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);

                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(privkeyTa);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                free(curves);
                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(user_id);
                free(Ta_buf);
                free(u_Auth);
                free(w_auth);
                free(hash_in);
                free(privkeyTa_buf);
                free(K);
                free(u_s_Auth);
                free(hmac_in);
                free(Tb_buf);
                free(rnd_rs_buf);
                free(s_Auth);
                free(s_ID);
                free(abP_buf);
                free(u_n);
                free(s_n);
                printf("u_n auth err\n");
                return -1;
        }
        printf("u_n auth suc\n");

        char replay[RE_MAX_LENGTH];
        bzero(replay, RE_MAX_LENGTH);
        strcpy(replay, "auth_OK");
        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
        {
                BN_CTX_free(ctx);
                EC_KEY_free(key);
                EC_GROUP_free(group);
                BN_free(p);
                BN_free(a);
                BN_free(b);
                BN_free(rnd_b);
                BN_free(rnd_rs);

                EC_POINT_free(Ta);
                EC_POINT_free(Tb);
                EC_POINT_free(abP);
                EC_POINT_free(privkeyTa);

                free(curves);
                free(p_buf);
                free(pubkey_buf);
                free(Ta_buf);
                free(Tb_buf);
                free(privkeyTa_buf);
                free(rnd_rs_buf);
                free(abP_buf);
                free(hash_in);
                free(hmac_in);
                free(K);
                free(user_id);
                free(w_auth);
                free(u_Auth);
                free(u_s_Auth);
                free(u_n);
                free(s_n);
                free(s_Auth);
                free(s_ID);
                printf("replay recv err\n");
                return ret;
        }

        BN_CTX_free(ctx);
        EC_KEY_free(key);
        EC_GROUP_free(group);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(rnd_b);
        BN_free(rnd_rs);

        EC_POINT_free(Ta);
        EC_POINT_free(Tb);
        EC_POINT_free(abP);
        EC_POINT_free(privkeyTa);

        free(curves);
        free(p_buf);
        free(pubkey_buf);
        free(Ta_buf);
        free(Tb_buf);
        free(privkeyTa_buf);
        free(rnd_rs_buf);
        free(abP_buf);
        free(hash_in);
        free(hmac_in);
        free(K);
        free(user_id);
        free(w_auth);
        free(u_Auth);
        free(u_s_Auth);
        free(u_n);
        free(s_n);
        free(s_Auth);
        free(s_ID);

        printf("server_auth finished!\n");

        return MD5SIZE;
}
