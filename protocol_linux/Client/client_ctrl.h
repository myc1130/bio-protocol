#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define port 5555
#define BUFMAX 1024
#define MD5SIZE 16
#define HASHSIZE 16
#define HMACSIZE 1024
#define MAX_PATH 256
#define RE_MAX_LENGTH 32
#define FUN_MAX_LENGTH 32
#define ID_MAX_LENGTH 16
#define PW_MAX_LENGTH 16

typedef struct print_options
{
        char printer_name[64];        //
        char color[16];         //Colorful print，default false
        char media[16];         //paper type, default a4
        char sides[32];         //whether two-side print and the direction, can be:one-sided,two-sided-long-edge,two-sided-short-edge
        int num_copies;         //copies of
        char pages_list[64];         //the range of print
        int num_up;         //the pages on every paper, can be:2,4,6,9,16
        char num_up_layout[16];         //the layout of print, can be:"btlr", "btrl", "lrbt", "lrtb", "rlbt", "rltb", "tblr", or "tbrl"
        int priority;         //the priority of print, default 50
}PrintOpts;

/** Init the socket of client
 *  \return socket on success and 0 if an error occured
 */
int client_socket_init(char *addr);

/** Send the message through socket
 *  \param  sockfd     socket
 *  \param  buf        the message
 *  \param  buf_len    the length of message
 *  \return the length of message on success and error code if an error occured
 */
int client_socket_send(int sockfd, char *buf, size_t buf_len);

/** Receive the message through socket
 *  \param  sockfd     socket
 *  \param  buf        the message
 *  \param  buf_len    the max length of message
 *  \return the length of message on success and error code if an error occured
 */
int client_socket_recv(int sockfd, char *buf, size_t buf_len);

/** Inquire whether the user_id exists in database
 *  \param  sockfd      socket
 *  \param  user_id     the user_id
 *  \return -1 if the user_id exists and 1 if the user_id do not exists and 0 if an error occured
 */
int client_mysql_inquire(int sockfd, char *user_id);

/** Get the help_data from database
 *  \param  mysql                mysql
 *  \param  user_id              the user_id
 *  \param  help_data            the help_data
 *  \param  help_data_length     the max length of help_data
 *  \return the length of help_data on success and error code if an error occured
 */
int client_mysql_gethelpdata(int sockfd, char *user_id, char *help_data, int help_data_length);

/** Calculate the MD5 of message
 *  \param  buf               message
 *  \param  buf_len           the length of message
 *  \param  md5sum            the MD5 of message
 *  \return 0 on success and error code if an error occured
 */
int client_md5sum(char *buf, int buf_len, char *md5sum);

/** Compare the MD5 of message and the given MD5
 *  \param  buf               message
 *  \param  buf_len           the length of message
 *  \param  md5sum            the compared MD5
 *  \return 0 if the MD5 of message is equal to the given MD5 and -1 otherwise
 */
int client_md5check(char *buf, int buf_len, char *md5sum);

/** Calculate the MD5 sum of file
 *  \param  file_path         the path of file
 *  \param  md5sum            the MD5 of message
 *  \return 0 on success and error code if an error occured
 */
int client_md5sum_file(char *file_path, char *md5sum);

/** Compare the MD5 of message and the given MD5
 *  \param  file_path         the path of file
 *  \param  md5sum            the compared MD5
 *  \return 0 if the MD5 of file is equal to the given MD5 and -1 otherwise
 */
int client_md5check_file(char *file_path, char *md5sum);

/** Send a message through a secure channel
 *  \param  sockfd          socket
 *  \param  buf             the message
 *  \param  buf_len         the length of message
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return the length of message on success and error code if an error occured
 */
int client_sc_send(int sockfd, char *buf, int buf_len, char *us_sk, int us_sk_length);

/** Receive a message through a secure channel
 *  \param  sockfd          socket
 *  \param  buf             the message
 *  \param  buf_len         the length of message
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return the length of message on success and error code if an error occured
 */
int client_sc_recv(int sockfd, char *buf, int buf_len, char *us_sk, int us_sk_length);

/** Send a file through a secure channel
 *  \param  sockfd          socket
 *  \param  file_path       the path of file
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int client_sc_send_file(int sockfd, char *file_path, char *us_sk, int us_sk_length);

/** Receive a file through a secure channel
 *  \param  sockfd          socket
 *  \param  file_path       the path of file
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int client_sc_recv_file(int sockfd, char *file_path, char *us_sk, int us_sk_length);

/** Ask the server to auth a user
 *  \param  sockfd          socket
 *  \param  user_id         the user's id
 *  \param  user_pw         the user's password
 *  \param  bio_key         the user's bio key
 *  \param  bio_key_length  the length of bio_key
 *  \param  us_sk           session key
 *  \return the length of session key on success and error code if an error occured
 */
int client_auth(int sockfd, char *user_id, char *user_pw,
                char *bio_key, int bio_key_length, char *us_sk);

/** Ask the server to register a user
 *  \param  sockfd          socket
 *  \param  user_id         the user's id
 *  \param  user_pw         the user's password
 *  \param  help_data            the help_data
 *  \param  help_data_length     the max length of help_data
 *  \param  bio_key         the user's bio key
 *  \param  bio_key_length  the length of bio_key
 *  \return 0 on success and error code if an error occured
 */
int client_register(int sockfd, char *user_id, char *user_pw, char *help_data,
                    int help_data_length, char *bio_key, int bio_key_length);

/** Send the file to the server
 *  \param  sockfd          socket
 *  \param  us_sk           session key
 *  \param  file_path       the file path
 *  \param  md5sum          the MD5 sum
 *  \param  rndnum          the random number
 *  \param  rndnum_len      the length of random number
 *  \param  opts            the print options
 *  \param  us_sk           session key
 *  \param  us_sk_length    the length of session key
 *  \return 0 on success and error code if an error occured
 */
int client_file_send(int sockfd, char *user_id, char *file_path, char *md5sum,
                     char *rndnum, int rndnum_len, PrintOpts *opts, char *us_sk, int us_sk_length);

/** Compare two memory
 *  \param  a         memory a
 *  \param  b         memory b
 *  \param  a_len     the length of memory a
 *  \param  b_len     the length of memory b
 *  \return 0 if two memory is equal and others otherwise
 */
int client_check(char *a, char *b, size_t a_len, size_t b_len);

/** Catenate two memory
 *  \param  dest      the dest memory
 *  \param  src       the source memory
 *  \param  dest_len  the length of dest memory
 *  \param  src_len   the length of source memory
 */
void client_memcat(char *dest, char *src, size_t *dest_len, size_t src_len);

/** Output the memory
 *  \param  src       the source memory
 *  \param  src_len   the length of source memory
 */
void client_output(char *src, size_t src_len);

/** Show error messages
 */
void client_err_msg();

/** Handle errors
 *  \param  sockfd    socket
 *  \param  err_num   the error
 */
void client_err_handle(int sockfd, int err_num);

/** Encrypt the file
 *  \param  src_file_path   the path of source file
 *  \param  dst_file_path   the path of dest file
 *  \param  key             the encryption key
 *  \param  key_length      the length of encryption key
 *  \return 0 on success and error code if an error occured
 */
int file_encrypt(char *src_file_path, char *dst_file_path, char *key, int key_length);
int anetKeepAlive(char *err, int fd, int interval);
