FROM ubuntu:latest

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && \
	apt-get install -y git make gcc curl zlib1g-dev libpcre3-dev

ADD . /build/nginx-ssl-fingerprint/
ADD ./Makefile /build/

WORKDIR /build

RUN git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl && \
    git clone -b branches/stable-1.18 https://github.com/nginx/nginx 


RUN make patch && \
    make build && \
    mkdir logs && \
    openssl ecparam -genkey -name prime256v1 | tee ./nginx-ssl-fingerprint/cert.pem | openssl req -x509 -nodes -key /dev/stdin -days 366 -subj '/C=US/OU=Web/CN=example.org' | tee -a ./nginx-ssl-fingerprint/cert.pem

EXPOSE 443
EXPOSE 8444

CMD ./nginx/objs/nginx -p /build -c nginx-ssl-fingerprint/conf/nginx.conf
