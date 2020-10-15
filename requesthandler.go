package razproxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/miekg/dns"
)

type requestHandler struct {
	mtx          sync.Mutex
	reqLogFilter map[string]bool
	srv          *Server
}

func (rh *requestHandler) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	go rh.logRequest(req.RemoteAddr.String(), " -> ", req.DestAddr.String())
	return ctx, !isPrivateIP(req.DestAddr.IP)
}

func (rh *requestHandler) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ip, err := rh.resolve(name)
	go rh.logRequest("DNS request:", name, " -> ", ip)
	return ctx, ip, err
}

func (rh *requestHandler) resolve(name string) (net.IP, error) {
	if len(rh.srv.ExternalDNS) > 0 {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.MsgHdr.RecursionDesired = true
		req.Question = []dns.Question{
			{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: dns.Fqdn(name), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		}
		req.SetEdns0(4096, true)
		answer, _, err := new(dns.Client).Exchange(req, rh.srv.ExternalDNS)
		if err != nil {
			return nil, err
		}
		if answer.Rcode != 0 {
			return nil, fmt.Errorf("DNS error: %d", answer.Rcode)
		}
		for _, a := range answer.Answer {
			switch a := a.(type) {
			case (*dns.A):
				return a.A, nil
			case (*dns.AAAA):
				return a.AAAA, nil
			}
		}
		return nil, fmt.Errorf("no result")
	}

	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return nil, err
	}
	return addr.IP, err
}

func (rh *requestHandler) logRequest(a ...interface{}) {
	rh.mtx.Lock()
	defer rh.mtx.Unlock()

	if rh.reqLogFilter == nil {
		rh.reqLogFilter = make(map[string]bool)
	}

	reqStr := fmt.Sprint(a...)
	if !rh.reqLogFilter[reqStr] {
		rh.reqLogFilter[reqStr] = true
		rh.srv.Logger.Println(reqStr)
		go func() {
			<-time.NewTimer(time.Minute * 5).C
			rh.mtx.Lock()
			defer rh.mtx.Unlock()
			delete(rh.reqLogFilter, reqStr)
		}()
	}
}
