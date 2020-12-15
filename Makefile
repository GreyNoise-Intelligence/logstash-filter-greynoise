MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))

DOCKER_IMAGE_TAG := logstash-gn-dev
DOCKER_ARGS ?= -v $(MKFILE_DIR):/usr/src/app -w /usr/src/app

build-docker:
	@docker build . -t $(DOCKER_IMAGE_TAG)

shell-docker:
	@docker run -it $(DOCKER_ARGS) --entrypoint /bin/bash $(DOCKER_IMAGE_TAG)
