package razproxy

import (
	"context"
	"net"
)

type fakeDNS struct{}

func (dns fakeDNS) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
