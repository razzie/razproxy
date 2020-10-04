.PHONY: all client server
.DEFAULT_GOAL := all

all: client server

client:
	CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-client

server:
	CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -gcflags=-trimpath=$(CURDIR) ./cmd/razproxy-server
