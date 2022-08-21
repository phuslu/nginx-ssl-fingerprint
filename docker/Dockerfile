FROM ubuntu:22.10 AS nginx-stage

RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y git make gcc curl zlib1g-dev libpcre3-dev

ARG OPENSSL_VERSION
ARG NGINX_VERSION

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

EXPOSE 8444

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

FROM nginx-stage AS tests-stage

RUN curl https://go.dev/dl/go1.19.linux-amd64.tar.gz -L -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && rm -rf /tmp/go.tar.gz 
    
RUN export DEBIAN_FRONTEND=noninteractive && \
	apt-get update && \
	apt-get install -y netcat-openbsd

ENV PATH=/usr/local/go/bin:$PATH

RUN mkdir -p /build/nginx-ssl-fingerprint/docker/tests/
WORKDIR /build/nginx-ssl-fingerprint/docker/tests/

COPY ./docker/tests/go.mod ./docker/tests/go.sum /build/nginx-ssl-fingerprint/docker/tests/

RUN go mod download

COPY ./docker/tests /build/nginx-ssl-fingerprint/docker/tests/

RUN cp /build/nginx-ssl-fingerprint/docker/tests/cert.pem /usr/local/share/ca-certificates/cert.crt && \
    update-ca-certificates

RUN mkdir -p /build/run/logs

CMD /build/nginx-ssl-fingerprint/docker/tests/run-test.sh

