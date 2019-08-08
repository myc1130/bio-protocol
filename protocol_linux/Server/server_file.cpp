#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mysql.h>
#include "server_ctrl.h"

int server_file_recv(int new_fd, MYSQL mysql, char *us_sk, int us_sk_length)
{
        int ret = 0;

        char user_id[ID_MAX_LENGTH];
        memset(user_id, 0, ID_MAX_LENGTH);
        ret = server_sc_recv(new_fd, user_id, ID_MAX_LENGTH, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        char file_path[MAX_PATH];
        memset(file_path, 0, MAX_PATH);
        ret = server_sc_recv(new_fd, file_path, MAX_PATH, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        char *p = strrchr(file_path, '/');

        char file_name[MAX_PATH];
        memset(file_name, 0, MAX_PATH);
        if (p == NULL)
                strcpy(file_name, file_path);
        else
                strcpy(file_name, p + 1);

        char server_file_path[MAX_PATH];
        uid_t userid;
        struct passwd *pwd;
        userid = getuid();
        pwd = getpwuid(userid);
        memset(server_file_path, 0, MAX_PATH);
        strcpy(server_file_path, pwd->pw_dir);
        strcat(server_file_path, "/server_file/");
        if (access(server_file_path, F_OK) == -1)
                mkdir(server_file_path, 0777);

        strcat(server_file_path, user_id);
        strcat(server_file_path, "/");
        if (access(server_file_path, F_OK) == -1)
                mkdir(server_file_path, 0777);

        strcat(server_file_path, file_name);

        ret = server_sc_recv_file(new_fd, server_file_path, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        char md5sum[MD5SIZE];
        memset(md5sum, 0, MD5SIZE);
        ret = server_sc_recv(new_fd, md5sum, MD5SIZE, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        char rndnum[RNDNUM_MAX_LENGTH];
        memset(rndnum, 0, RNDNUM_MAX_LENGTH);
        ret = server_sc_recv(new_fd, rndnum, RNDNUM_MAX_LENGTH, us_sk, us_sk_length);
        if (ret < 0)
                return ret;

        PrintOpts *opts;
        opts = (PrintOpts *)malloc(sizeof(PrintOpts));
        memset(opts, 0, sizeof(PrintOpts));
        ret = server_sc_recv(new_fd, (char *)opts, sizeof(PrintOpts), us_sk, us_sk_length);
        if (ret < 0)
        {
                free(opts);
                return ret;
        }

        ret = server_file_add(mysql, user_id, server_file_path, rndnum, RNDNUM_MAX_LENGTH, opts, md5sum);
        if (ret < 0)
        {
                free(opts);
                return ret;
        }

        char replay[RE_MAX_LENGTH];
        memset(replay, 0, RE_MAX_LENGTH);
        strcpy(replay, "file_OK");
        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
        {
                free(opts);
                printf("replay recv err\n");
                return ret;
        }

        free(opts);
        return 0;
}

int server_file_add(MYSQL mysql, char *user_id, char *file_path, char *rndnum, int rndnum_len, PrintOpts *opts, char *md5sum)
{
        char query[QUERY_MAX_LENGTH];
        int query_len;
        char temp[BUFMAX];

        memset(query, 0, sizeof(query));
        query_len = 0;
        memset(temp, 0, sizeof(temp));
        strcpy(temp, "insert into user_files(user_id, file_path, rndnum, opts, md5sum) values('");
        memcpy(query, temp, strlen(temp));
        query_len += strlen(temp);

        memcpy(query + query_len, user_id, strlen(user_id));
        query_len += strlen(user_id);

        memset(temp, 0, sizeof(temp));
        strcpy(temp, "','");
        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, file_path, strlen(file_path));

        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, rndnum, rndnum_len);

        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, (char *)opts, sizeof(PrintOpts));

        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, md5sum, MD5SIZE);

        memset(temp, 0, sizeof(temp));
        strcpy(temp, "')");
        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        if (mysql_query(&mysql, query))
        {
                printf("insert err\n");
                return -204;
        }

        return 0;
}
