package razproxy

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/miekg/dns"
	"github.com/xtaci/smux"
)

// ServerSession ...
type ServerSession struct {
	id      string
	srv     *Server
	session *smux.Session

	mtx          sync.Mutex
	reqLogFilter map[string]bool
}

func (s *Server) newSession(conn io.ReadWriteCloser) (*ServerSession, error) {
	session, err := smux.Server(conn, nil)
	if err != nil {
		return nil, err
	}

	return &ServerSession{
		id:           UniqueID(),
		srv:          s,
		session:      session,
		reqLogFilter: make(map[string]bool),
	}, nil
}

func (s *ServerSession) run() {
	defer s.Close()

	s.log(s.session.RemoteAddr().String(), " connected")

	socks5Conf := &socks5.Config{
		Credentials: s.srv.auth,
		Resolver:    s,
		Rules:       s,
		Logger:      log.New(ioutil.Discard, "", 0),
	}
	socks5Srv, err := socks5.New(socks5Conf)
	if err != nil {
		s.log("socks5 error: ", err)
		return
	}

	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			s.log("stream error: ", err)
			return
		}
		go func() {
			defer stream.Close()
			socks5Srv.ServeConn(stream)
		}()
	}
}

// Close implements io.Closer
func (s *ServerSession) Close() error {
	s.log("connection closed")
	return s.session.Close()
}

// Allow implements socks5.RuleSet
func (s *ServerSession) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	go s.filterLog(req.DestAddr.String())
	return ctx, !isPrivateIP(req.DestAddr.IP)
}

// Resolve implements socks5.NameResolver
func (s *ServerSession) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ip, err := s.resolve(name)
	go s.filterLog("DNS: ", name, " -> ", ip)
	return ctx, ip, err
}

func (s *ServerSession) resolve(name string) (net.IP, error) {
	if len(s.srv.ExternalDNS) > 0 {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.MsgHdr.RecursionDesired = true
		req.Question = []dns.Question{
			{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: dns.Fqdn(name), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		}
		req.SetEdns0(4096, true)
		answer, _, err := new(dns.Client).Exchange(req, s.srv.ExternalDNS)
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

func (s *ServerSession) log(a ...interface{}) {
	s.srv.Logger.Printf("[%s] %s", s.id, fmt.Sprint(a...))
}

func (s *ServerSession) filterLog(a ...interface{}) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.reqLogFilter == nil {
		s.reqLogFilter = make(map[string]bool)
	}

	reqStr := fmt.Sprint(a...)
	if !s.reqLogFilter[reqStr] {
		s.reqLogFilter[reqStr] = true
		s.srv.Logger.Printf("[%s] %s", s.id, reqStr)
		go func() {
			<-time.NewTimer(time.Minute * 5).C
			s.mtx.Lock()
			defer s.mtx.Unlock()
			delete(s.reqLogFilter, reqStr)
		}()
	}
}
