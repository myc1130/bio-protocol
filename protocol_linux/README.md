# 网络安全打印机服务器

文件夹 Client 内是客户端相关代码<br>
文件夹 Server 内是服务器相关代码<br>
文件夹 Server_print 内是服务器打印模块相关代码

## 数据库:

#### 安装数据库
```
sudo apt-get install mysql-server
sudo apt-get install mysql-client
sudo apt-get install libmysqlclient-dev
```
管理用户名和密码都设为root

#### 启动数据库服务
```
service mysql start
```

#### 登录数据库
```
mysql -uroot -proot
```

#### 创建数据库
创建一个名为test的数据库
```
create database test;
```

#### 登录test数据库
```
use test;
```

#### 创建数据表
创建一个存储用户辅助信息和认证信息的数据表
```
create table bio(user_id varchar(20) not null,
                 help_data blob not null,
                 w_auth varchar(32) not null,
                 primary key(user_id));
```
创建一个存储用户打印文件相关信息的数据表
```
create table user_files(user_id varchar(20) not null,
                        file_path varchar(512) not null,
                        rndnum varchar(2048) not null,
                        opts varchar(512) not null,
                        md5sum, varchar(32) not null);
```

#### 注意事项
数据库和数据表的名字以及表中各项的名字不可随意更改，一旦更改，程序代码中对应的位置也需要更改

## OpenSSL:

#### 安装openssl
```
sudo apt-get install openssl
sudo apt-get install libssl-dev
```
