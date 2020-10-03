package main

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

const proxyAddr = "localhost:8000"

type tlsDialer struct {
	Config *tls.Config
}

func (d *tlsDialer) Dial(network, addr string) (net.Conn, error) {
	return tls.Dial(network, addr, d.Config)
}

func main() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &tlsDialer{Config: tlsConf})
	if err != nil {
		panic(err)
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "localhost:1080"); err != nil {
		panic(err)
	}
}
