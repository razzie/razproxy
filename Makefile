.PHONY: all client server
.DEFAULT_GOAL := all

all: client server

client:
	go build -mod=vendor -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-client

server:
	go build -mod=vendor -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-server
