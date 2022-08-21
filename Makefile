DOCKER_BASE_IMAGE=phuslu/nginx-ssl-fingerprint

OPENSSL_VERSION=OpenSSL_1_1_1-stable
NGINX_VERSION=release-1.23.1

DEPS_VERSIONS_SUFFIX=-${OPENSSL_VERSION}-${NGINX_VERSION}

DOCKER_NGINX_IMAGE=${DOCKER_BASE_IMAGE}:nginx${DEPS_VERSIONS_SUFFIX}
DOCKER_TLSFUZZER_IMAGE=${DOCKER_BASE_IMAGE}:tlsfuzzer${DEPS_VERSIONS_SUFFIX}
DOCKER_TESTS_IMAGE=${DOCKER_BASE_IMAGE}:tests${DEPS_VERSIONS_SUFFIX}

BUILD_ARGS=--build-arg "OPENSSL_VERSION=${OPENSSL_VERSION}" --build-arg "NGINX_VERSION=${NGINX_VERSION}"

.PHONY: build-nginx
build-nginx:
	docker build -t ${DOCKER_NGINX_IMAGE} ${BUILD_ARGS} -f docker/Dockerfile --target nginx-stage .
	
.PHONY: run-nginx
run-nginx: build-nginx
	docker run --rm -v $(PWD):/build/nginx-ssl-fingerprint -p 8444:8444 ${DOCKER_NGINX_IMAGE}

.PHONY: build-tlsfuzzer
build-tlsfuzzer:
	docker build -t ${DOCKER_TLSFUZZER_IMAGE} ${BUILD_ARGS} -f docker/Dockerfile --target tlsfuzzer-stage .
	
.PHONY: run-tlsfuzzer
run-tlsfuzzer: build-tlsfuzzer
	docker run --rm -v $(PWD):/build/nginx-ssl-fingerprint ${DOCKER_TLSFUZZER_IMAGE}

.PHONY: build-tests
build-tests:
	docker build -t ${DOCKER_TESTS_IMAGE} ${BUILD_ARGS} -f docker/Dockerfile --target tests-stage .
	
.PHONY: run-tests
run-tests: build-tests
	docker run --rm ${DOCKER_TESTS_IMAGE}

.PHONY: run-tests-matrix
run-tests-matrix:
	make OPENSSL_VERSION=OpenSSL_1_1_1q NGINX_VERSION=release-1.23.1 run-tests
	make OPENSSL_VERSION=OpenSSL_1_1_1q NGINX_VERSION=release-1.22.0 run-tests
	@echo OK
