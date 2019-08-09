cc = g++
target = server

server:server_auth.cpp server_ctrl.cpp server_ctrl.h server_err.cpp server_file.cpp server_help.cpp server_md5.cpp server_mysql.cpp server_register.cpp server_sc.cpp server_socket.cpp
##	g++ server_auth.cpp server_ctrl.cpp server_ctrl.h server_err.cpp server_file.cpp server_help.cpp server_md5.cpp server_mysql.cpp server_register.cpp server_sc.cpp server_socket.cpp -o server -I/usr/include/mysql -L/usr/lib64/mysql -lssl -lcrypto -lmysqlclient
	g++-9 server_auth.cpp server_ctrl.cpp server_ctrl.h server_err.cpp server_file.cpp server_help.cpp server_md5.cpp server_mysql.cpp server_register.cpp server_sc.cpp server_socket.cpp -o server -I/usr/local/opt/openssl/include -I/usr/local/opt/mysql/include/mysql -I/usr/local/opt/mysql/include  -L/usr/local/opt/openssl/lib -L/usr/local/opt/mysql/lib -lssl -lcrypto -lmysqlclient
.PHONY: clean
clean :
	-rm -f *.o $(target)
