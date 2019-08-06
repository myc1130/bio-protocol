#include <dlfcn.h>
#include "client_ctrl.h"

int client_mysql_inquire(int sockfd, char *user_id)
{
								int ret;

								char fun[FUN_MAX_LENGTH];
								char replay[RE_MAX_LENGTH];

								bzero(fun, sizeof(fun));
								strcpy(fun, "mysql_inquire");
								ret = client_socket_send(sockfd, fun, strlen(fun));
								if (ret < 0)
																return ret;

								ret = client_socket_send(sockfd, user_id, strlen(user_id));
								if (ret < 0)
																return ret;

								bzero(replay, sizeof(replay));
								ret = client_socket_recv(sockfd, replay, sizeof(replay));

								if (ret < 0)
																return ret;

								if (strcmp(replay, "ID_exist") == 0)
								{
																return -1;
								}

								return 0;
}

int client_mysql_gethelpdata(int sockfd, char *user_id, char *help_data, int help_data_length)
{
								int ret;

								char fun[FUN_MAX_LENGTH];
								char replay[RE_MAX_LENGTH];

								bzero(fun, sizeof(fun));
								strcpy(fun, "get_helpdata");
								ret = client_socket_send(sockfd, fun, strlen(fun));
								if (ret < 0)
																return ret;

								ret = client_socket_send(sockfd, user_id, strlen(user_id));
								if (ret < 0)
																return ret;

								bzero(replay, sizeof(replay));
								ret = client_socket_recv(sockfd, replay, sizeof(replay));
								if (ret < 0)
																return ret;
								if (strcmp(replay, "get_helpdata_OK") == 0)
								{
																help_data_length = client_socket_recv(sockfd, help_data, help_data_length);
																if (help_data_length < 0)
																								return help_data_length;
								}
								else
								{
																return -1;
								}

								return help_data_length;
}
