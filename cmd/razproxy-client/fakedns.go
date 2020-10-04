package main

import (
	"context"
	"net"
)

type fakeDNS struct{}

func (dns fakeDNS) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

/*func (dns dnsProxy) Rewrite(ctx context.Context, request *socks5.Request) (context.Context, *socks5.AddrSpec) {

}*/
