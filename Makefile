.PHONY: all client server
.DEFAULT_GOAL := all

all: client server

client:
	go build -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-client

server:
	go build -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-server
