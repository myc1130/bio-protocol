cc = g++
target = client
deps = client_ctrl.h
obj = client_auth.o client_check.o client_ctrl.o client_register.o client_socket.o
LIBS = -lssl -lcrypto

client: client_auth.cpp client_ctrl.cpp client_ctrl.h client_err.cpp client_file.cpp client_help.cpp client_md5.cpp client_mysql.cpp client_register.cpp client_sc.cpp client_socket.cpp file_encrypt.cpp
##	g++ client_auth.cpp client_ctrl.cpp client_ctrl.h client_err.cpp client_file.cpp client_help.cpp client_md5.cpp client_mysql.cpp client_register.cpp client_sc.cpp client_socket.cpp file_encrypt.cpp -o client -I/usr/local/Cellar/openssl/1.0.2o_2/include -L/usr/local/Cellar/openssl/1.0.2o_2/lib -lssl -lcrypto
	g++-9 client_auth.cpp client_ctrl.cpp client_ctrl.h client_err.cpp client_file.cpp client_help.cpp client_md5.cpp client_mysql.cpp client_register.cpp client_sc.cpp client_socket.cpp file_encrypt.cpp -o client -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
.PHONY: clean
clean :
	-rm -f *.o $(target)
