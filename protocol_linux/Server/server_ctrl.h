#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define port 5555
#define BUFMAX 1024
#define MD5SIZE 16
#define HASHSIZE 16
#define HMACSIZE 1024
#define MAX_PATH 256
#define HLDA_MAX_LENGTH 7028
#define RNDNUM_MAX_LENGTH 1024
#define RE_MAX_LENGTH 32
#define FUN_MAX_LENGTH 32
#define ID_MAX_LENGTH 16
#define PW_MAX_LENGTH 16
#define QUERY_MAX_LENGTH 20000

typedef struct print_options
{
        char printer_name[64];  //
        char color[16];         //Colorful print，default false
        char media[16];         //paper type, default a4
        char sides[32];         //whether two-side print and the direction, can be:one-sided,two-sided-long-edge,two-sided-short-edge
        int num_copies;         //copies of
        char pages_list[64];    //the range of print
        int num_up;             //the pages on every paper, can be:2,4,6,9,16
        char num_up_layout[16]; //the layout of print, can be:"btlr", "btrl", "lrbt", "lrtb", "rlbt", "rltb", "tblr", or "tbrl"
        int priority;           //the priority of print, default 50
} PrintOpts;

/** Init the socket of server
 *  \return socket on success and error code if an error occured
 */
int server_socket_init();

/** Send the message through socket
 *  \param  new_fd     socket
 *  \param  buf        the message
 *  \param  buf_len    the length of message
 *  \return the length of message on success and error code if an error occured
 */
int server_socket_send(int new_fd, char *buf, size_t buf_len);

/** Receive the message through socket
 *  \param  new_fd     socket
 *  \param  buf        the message
 *  \param  buf_len    the max length of message
 *  \return the length of message on success and error code if an error occured
 */
int server_socket_recv(int new_fd, char *buf, size_t buf_len);

/** Init the connect of mysql
 *  \return mysql on success and NULL if an error occured
 */
MYSQL server_mysql_init();

/** Insert the data into database
 *  \param  mysql                mysql
 *  \param  user_id              the data user_id
 *  \param  id_len               the length of user_id
 *  \param  help_data            the data help_data
 *  \param  help_data_length     the length of help_data
 *  \param  w_auth               the data w_auth
 *  \param  w_auth_length        the length of w_auth
 *  \return 0 on success and error code if an error occured
 */
int server_mysql_insert(MYSQL mysql, char *user_id, int id_len, char *help_data,
                        int help_data_length, char *w_auth, int w_auth_len);

/** Inquire whether the user_id exists in database
 *  \param  new_fd      socket
 *  \param  mysql       mysql
 *  \return 0 on success and error code if an error occured
 */
int server_mysql_inquire(int new_fd, MYSQL mysql);

/** Get the w_auth from database
 *  \param  mysql                mysql
 *  \param  user_id              the user_id
 *  \param  w_auth               the w_auth
 *  \return the length of w_auth on success and error code if an error occured
 */
int server_mysql_getwauth(MYSQL mysql, char *user_id, char *w_auth);

/** Get the help_data from database
 *  \param  new_fd               socket
 *  \param  mysql                mysql
 *  \return 0 on success and error code if an error occured
 */
int server_mysql_gethelpdata(int new_fd, MYSQL mysql);

/** Calculate the MD5 of message
 *  \param  buf               message
 *  \param  buf_len           the length of message
 *  \param  md5sum            the address to store the MD5 of message
 *  \return 0 on success and error code if an error occured
 */
int server_md5sum(char *buf, int buf_len, char *md5sum);

/** Compare the MD5 of message and the given MD5
 *  \param  buf               message
 *  \param  buf_len           the length of message
 *  \param  md5sum            the compared MD5
 *  \return 0 if the MD5 of message is equal to the given MD5 and -1 otherwise
 */
int server_md5check(char *buf, int buf_len, char *md5sum);

/** Calculate the MD5 sum of file
 *  \param  file_path         the path of file
 *  \param  md5sum            the address to store the MD5 of message
 *  \return 0 on success and error code if an error occured
 */
int server_md5sum_file(char *file_path, char *md5sum);

/** Compare the MD5 of message and the given MD5
 *  \param  file_path         the path of file
 *  \param  md5sum            the compared MD5
 *  \return 0 if the MD5 of file is equal to the given MD5 and -1 otherwise
 */
int server_md5check_file(char *file_path, char *md5sum);

/** Send a message through a secure channel
 *  \param  new_fd          socket
 *  \param  buf             the message
 *  \param  buf_len         the length of message
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return the length of message on success and error code if an error occured
 */
int server_sc_send(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length);

/** Receive a message through a secure channel
 *  \param  new_fd          socket
 *  \param  buf             the message
 *  \param  buf_len         the length of message
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return the length of message on success and error code if an error occured
 */
int server_sc_recv(int new_fd, char *buf, int buf_len, char *us_sk, int us_sk_length);

/** Send a file through a secure channel
 *  \param  new_fd          socket
 *  \param  file_path       the path of file
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int server_sc_send_file(int new_fd, char *file_path, char *us_sk, int us_sk_length);

/** Receive a file through a secure channel
 *  \param  new_fd          socket
 *  \param  file_path       the path of file
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int server_sc_recv_file(int new_fd, char *file_path, char *us_sk, int us_sk_length);

/** Auth the client
 *  \param  new_fd          socket
 *  \param  mysql           mysql
 *  \param  us_sk           session key
 *  \return the length of session key on success and error code if an error occured
 */
int server_auth(int new_fd, MYSQL mysql, char *us_sk);

/** Complete the register of user
 *  \param  new_fd          socket
 *  \param  mysql           mysql
 *  \return 0 on success and error code if an error occured
 */
int server_register(int new_fd, MYSQL mysql);

/** Receive the file from the client
 *  \param  mysql           mysql
 *  \param  new_fd          socket
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int server_file_recv(int new_fd, MYSQL mysql, char *us_sk, int us_sk_length);

/** Add the file to the database
 *  \param  mysql           mysql
 *  \param  user_id         the user_id
 *  \param  file_path       the path of file
 *  \param  rndnum          the randum number
 *  \param  rndnum_len      the length of randum number
 *  \param  opts            the printf options
 *  \param  md5sum          the md5 of plain
 *  \return 0 on success and error code if an error occured
 */
int server_file_add(MYSQL mysql, char *user_id, char *file_path,
                    char *rndnum, int rndnum_len, PrintOpts *opts, char *md5sum);

/** Compare two memory
 *  \param  a         memory a
 *  \param  b         memory b
 *  \param  a_len     the length of memory a
 *  \param  b_len     the length of memory b
 *  \return 0 if two memory is equal and -1 or 1 otherwise
 */
int server_check(char *a, char *b, size_t a_len, size_t b_len);

/** Catenate two memory
 *  \param  dest      the dest memory
 *  \param  src       the source memory
 *  \param  dest_len  the length of dest memory
 *  \param  src_len   the length of source memory
 */
void server_memcat(char *dest, char *src, size_t *dest_len, size_t src_len);

/** Output the memory
 *  \param  src       the source memory
 *  \param  src_len   the length of source memory
 */
void server_output(char *src, size_t src_len);
/** Show error messages
 */
void server_err_msg();

/** Handle errors
 *  \param  new_fd    socket
 *  \param  err_num   the error code
 */
void server_err_handle(int new_fd, int err_num);
int anetKeepAlive(char *err, int fd, int interval);
