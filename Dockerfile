FROM ubuntu:latest

RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y git make gcc curl zlib1g-dev libpcre3-dev

ADD . /build/nginx-ssl-fingerprint/

WORKDIR /build

RUN git clone -b OpenSSL_1_1_1-stable --depth=1 https://github.com/openssl/openssl && \
    git clone -b release-1.23.1 --depth=1 https://github.com/nginx/nginx && \
    openssl ecparam -genkey -name prime256v1 | tee ./nginx-ssl-fingerprint/cert.pem | openssl req -x509 -nodes -key /dev/stdin -days 366 -subj '/C=US/OU=Web/CN=example.org' | tee -a ./nginx-ssl-fingerprint/cert.pem && \
    mkdir -p logs

RUN patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch && \
    patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch && \
    cd nginx && \
    ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan" && \
    make

EXPOSE 8444

CMD ./nginx/objs/nginx -p /build -c nginx-ssl-fingerprint/nginx.conf
