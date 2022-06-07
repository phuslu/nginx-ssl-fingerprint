SERVICE := nginx-ssl-fingerprint

all: help

help: ## Show help messages
	@echo "Container - ${SERVICE} "
	@echo
	@echo "Usage:\tmake COMMAND"
	@echo
	@echo "Commands:"
	@sed -n '/##/s/\(.*\):.*##/  \1#/p' ${MAKEFILE_LIST} | grep -v "MAKEFILE_LIST" | column -t -c 2 -s '#'

patch: ## patch nginx and openssl
	patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch
	patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch

build: ## Configure & Build nginx 
	cd nginx && \
			ASAN_OPTIONS=symbolize=1 ./auto/configure \
			--with-openssl=../openssl \
			--add-module=../nginx-ssl-fingerprint \
			--with-http_ssl_module \
			--with-stream_ssl_module \
			--with-debug --with-stream \
			--with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" \
			--with-ld-opt="-L/usr/local/lib -Wl,-E -lasan" && \
			make

docker: ## Create and start containers
	sudo docker-compose build --no-cache
	sudo docker-compose up -d --force-recreate


bash: ## Execute a command in a running container
	sudo docker-compose exec ${SERVICE} bash
