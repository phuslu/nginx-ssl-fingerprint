FROM ubuntu:22.10 AS nginx-stage

RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y git make gcc curl zlib1g-dev libpcre3-dev

ARG OPENSSL_VERSION=OpenSSL_1_1_1-stable
ARG NGINX_VERSION=release-1.23.1

WORKDIR /build

RUN git clone -b ${OPENSSL_VERSION} --depth=1 https://github.com/openssl/openssl && \
    git clone -b ${NGINX_VERSION} --depth=1 https://github.com/nginx/nginx

ADD patches/ /build/nginx-ssl-fingerprint/patches/
ADD src/ /build/nginx-ssl-fingerprint/src/
ADD config nginx.conf /build/nginx-ssl-fingerprint/

RUN patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch && \
    patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch && \
    cd nginx && \
    ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan" && \
    make

EXPOSE 4433

CMD ./nginx/objs/nginx -p /build -c nginx-ssl-fingerprint/nginx.conf

FROM nginx-stage AS tlsfuzzer-stage

RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y git make python3-pip python3 nginx
    
RUN git clone -b master --depth=1 https://github.com/tlsfuzzer/tlsfuzzer /build/tlsfuzzer

RUN pip install --no-cache-dir -r /build/tlsfuzzer/requirements.txt && \
    pip install --no-cache-dir -r /build/tlsfuzzer/requirements-timing.txt
  
ENV PYTHONPATH=/build/tlsfuzzer
COPY ./docker/tlsfuzzer /build/nginx-ssl-fingerprint/docker/tlsfuzzer/

RUN mkdir -p /build/run/logs

CMD /build/nginx-ssl-fingerprint/docker/tlsfuzzer/run-test.sh

