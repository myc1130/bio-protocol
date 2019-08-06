#include <dlfcn.h>
#include <mysql/mysql.h>
#include "server_ctrl.h"

MYSQL server_mysql_init()
{
        MYSQL mysql;
        if (mysql_init(&mysql) == NULL)
        {
                printf("func mysql_init() err :%d\n", mysql_errno(&mysql));
                return mysql;
        }

        if (mysql_real_connect(&mysql, "localhost", "root", "root", "test", 0, NULL, 0 ) == NULL)
        {
                printf("server_mysql_connect err :%d\n", mysql_errno(&mysql));
        }

        return mysql;
}

int server_mysql_insert(MYSQL mysql, char *user_id, int id_len, char *help_data, int help_data_length, char *w_auth, int w_auth_len)
{
        char query[QUERY_MAX_LENGTH];
        int query_len;
        char temp[BUFMAX];

        bzero(query, sizeof(query));
        query_len = 0;
        bzero(temp, sizeof(temp));
        strcpy(temp, "insert into bio(user_id, help_data, w_auth) values('");
        memcpy(query, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, user_id, id_len);

        bzero(temp, sizeof(temp));
        strcpy(temp, "','");
        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, help_data, help_data_length);

        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        query_len += mysql_real_escape_string(&mysql, query + query_len, w_auth, w_auth_len);

        bzero(temp, sizeof(temp));
        strcpy(temp, "')");
        memcpy(query + query_len, temp, strlen(temp));
        query_len += strlen(temp);

        if (mysql_query(&mysql, query))
        {
                printf("\n");
                printf("insert err\n");
                return -204;
        }

        return 0;
}

int server_mysql_inquire(int new_fd, MYSQL mysql)
{
        int ret;

        char user_id[ID_MAX_LENGTH];
        char replay[RE_MAX_LENGTH];
        bzero(user_id, ID_MAX_LENGTH);
        ret = server_socket_recv(new_fd, user_id, ID_MAX_LENGTH);
        if (ret < 0)
                return ret;

        char query[QUERY_MAX_LENGTH];

        bzero(query, sizeof(query));
        sprintf(query, "select * from bio where user_id='%s'", user_id);
        if (mysql_query(&mysql, query))
        {
                printf("select err\n");
                return -202;
        }

        MYSQL_RES *res;
        int count = 0;
        res = mysql_store_result(&mysql);
        count = mysql_num_rows(res);
        bzero(replay, RE_MAX_LENGTH);
        if (count <= 0)
        {
                strcpy(replay, "ID_not_exist");
        }
        else
        {
                strcpy(replay, "ID_exist");
        }

        mysql_free_result(res);

        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
                return ret;

        return 0;
}

int server_mysql_getwauth(MYSQL mysql, char *user_id, char *w_auth)
{
        int w_auth_len;

        char query[QUERY_MAX_LENGTH];
        bzero(query, sizeof(query));
        sprintf(query, "select w_auth from bio where user_id='%s'", user_id);
        if (mysql_query(&mysql, query))
        {
                printf("select err\n");
                return -202;
        }
        MYSQL_RES *res;
        res = mysql_store_result(&mysql);
        if (res)
        {
                MYSQL_ROW sql_row;
                unsigned long int *sql_row_lengths;

                if ((sql_row = mysql_fetch_row(res)) && (sql_row_lengths = mysql_fetch_lengths(res)))
                {
                        w_auth_len = sql_row_lengths[0];
                        bzero(w_auth, HASHSIZE);
                        memcpy(w_auth, sql_row[0], w_auth_len);
                }
                else
                {
                        mysql_free_result(res);
                        printf("mysql_fetch_row err\n");
                        return -203;
                }
        }

        mysql_free_result(res);

        return w_auth_len;
}

int server_mysql_gethelpdata(int new_fd, MYSQL mysql)
{
        int ret;

        int help_data_length;

        char replay[RE_MAX_LENGTH];
        char query[QUERY_MAX_LENGTH];
        char user_id[ID_MAX_LENGTH];

        bzero(user_id, sizeof(user_id));
        ret = server_socket_recv(new_fd, user_id, sizeof(user_id));
        if (ret < 0)
                return ret;

        char *help_data;
        help_data = (char *)malloc(HLDA_MAX_LENGTH * sizeof(char));
        bzero(help_data, HLDA_MAX_LENGTH);

        bzero(replay, sizeof(replay));
        strcpy(replay, "get_helpdata_failed");

        bzero(query, sizeof(query));
        sprintf(query, "select help_data from bio where user_id='%s'", user_id);
        if (mysql_query(&mysql, query))
        {
                free(help_data);
                printf("select err\n");
                return -202;
        }
        MYSQL_RES *res;
        res = mysql_store_result(&mysql);
        if (res)
        {
                MYSQL_ROW sql_row;
                unsigned long int *sql_row_lengths;

                if ((sql_row = mysql_fetch_row(res)) && (sql_row_lengths = mysql_fetch_lengths(res)))
                {
                        help_data_length = sql_row_lengths[0];
                        bzero(help_data, HLDA_MAX_LENGTH);
                        memcpy(help_data, sql_row[0], help_data_length);
                }
                else
                {
                        mysql_free_result(res);
                        free(help_data);
                        printf("mysql_fetch_row err\n");
                        return -203;
                }
        }

        bzero(replay, sizeof(replay));
        strcpy(replay, "get_helpdata_OK");

        ret = server_socket_send(new_fd, replay, strlen(replay));
        if (ret < 0)
        {
                mysql_free_result(res);
                free(help_data);
                return ret;
        }

        ret = server_socket_send(new_fd, help_data, help_data_length);
        if (ret < 0)
        {
                mysql_free_result(res);
                free(help_data);
                return ret;
        }

        mysql_free_result(res);
        free(help_data);
        return 0;

}
