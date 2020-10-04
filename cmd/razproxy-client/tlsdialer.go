package main

import (
	"crypto/tls"
	"net"
)

// TODO: to be removed after upgrading to go 1.15

type tlsDialer struct {
	Config *tls.Config
}

func (d *tlsDialer) Dial(network, addr string) (net.Conn, error) {
	return tls.Dial(network, addr, d.Config)
}
