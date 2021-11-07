# SQLite Nginx HTTP module

Nginx HTTP module that provides an HTTP API for interacting with a local SQLite database.

---

Add SQL statements to nginx.conf, then POST the parameter data as CSV data. Use GET if there are no parameters in the SQL statement.

Example nginx.conf locations:

```
location = /sql/select {
    sqlite_query 'select * from table1 where name=?1';
}
location = /sql/update {
    sqlite_query 'update table1 set number=?1 where name=?2';
}
location = /sql/insert {
    sqlite_query 'insert into table1(name,number) values (?1,?2)';
}
location = /sql/delete {
    sqlite_query 'delete from table1 where name=?1';
}
```

## Usage

Input is CSV data to provide parameters to prepared SQL statements. Field 1 of a row is bound to parameter 1 et cetera. Multiple rows will execute the same statement multiple times but with different parameters. The response contains all the resulting data.

Example request (input is CSV):

```sh
curl 'http://localhost:8888/sql/insert' --data 'Foo,11
Bar,22
Baz,33'

curl 'http://localhost:8888/sql/select' --data 'Foo
Bar
Baz'
```

Example response (output is CSV):

```
Foo,11
Bar,22
Baz,33
```

Specify database file in `http` block:

```
http {

  sqlite_database 'example.db';

  ...
}
```

## Building

```sh
# download nginx and build-tools
sudo dnf install -y --setopt=install_weak_deps=False \
  gcc binutils make wget openssl-devel pcre-devel zlib-devel
  # pcre-devel for ngx_http_rewrite_module
  # zlib-devel for ngx_http_gzip_static_module
wget https://nginx.org/download/nginx-1.18.0.tar.gz
tar zxf nginx-1.18.0.tar.gz

# plugin's curl-dependency
sudo dnf install sqlite-devel

# create a database
sqlite3 example.db
> create table table1(name text, number integer);
> CTRL+D
```

```sh
# configure, build, run
./build.sh configure
./build.sh build
./build.sh run
```
