DOCKER_BASE_IMAGE=phuslu/nginx-ssl-fingerprint
DOCKER_NGINX_IMAGE=${DOCKER_BASE_IMAGE}:nginx
DOCKER_TLSFUZZER_IMAGE=${DOCKER_BASE_IMAGE}:tlsfuzzer

.PHONY: build-nginx
build-nginx:
	docker build -t ${DOCKER_NGINX_IMAGE} -f docker/Dockerfile --target nginx-stage .
	
.PHONY: run-nginx
run-nginx: build-nginx
	docker run -it --rm -v $(PWD):/build/nginx-ssl-fingerprint -p 4433:4433 ${DOCKER_NGINX_IMAGE}

.PHONY: build-tlsfuzzer
build-tlsfuzzer:
	docker build -t ${DOCKER_TLSFUZZER_IMAGE} -f docker/Dockerfile --target tlsfuzzer-stage .
	
.PHONY: run-tlsfuzzer
run-tlsfuzzer: build-tlsfuzzer
	docker run -it --rm -v $(PWD):/build/nginx-ssl-fingerprint ${DOCKER_TLSFUZZER_IMAGE}
