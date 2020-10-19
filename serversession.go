package razproxy

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/rpc"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/miekg/dns"
	"github.com/xtaci/smux"
)

type serverSession struct {
	id            string
	srv           *Server
	session       *smux.Session
	authenticated bool
	logFilterMtx  sync.Mutex
	logFilter     map[string]bool
}

func (s *Server) newSession(conn io.ReadWriteCloser) (*serverSession, error) {
	session, err := smux.Server(conn, nil)
	if err != nil {
		return nil, err
	}

	return &serverSession{
		id:        uniqueID(),
		srv:       s,
		session:   session,
		logFilter: make(map[string]bool),
	}, nil
}

func (s *serverSession) run() {
	defer s.Close()

	s.log(s.session.RemoteAddr().String(), " connected")

	socks5Conf := &socks5.Config{
		//Credentials: s.srv.auth,
		Resolver: s,
		Rules:    s,
		Logger:   log.New(ioutil.Discard, "", 0),
	}
	socks5Srv, err := socks5.New(socks5Conf)
	if err != nil {
		s.log("socks5 error: ", err)
		return
	}

	rpcServ := rpc.NewServer()
	err = rpcServ.Register(&RPC{session: s})
	if err != nil {
		s.log("rpc error: ", err)
		return
	}

	rpcConn, err := s.session.AcceptStream()
	if err != nil {
		s.log("stream error: ", err)
		return
	}
	go func() {
		defer rpcConn.Close()
		rpcServ.ServeConn(rpcConn)
	}()

	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			if err != io.EOF {
				s.log("stream error: ", err)
			}
			return
		}
		if !s.authenticated {
			s.log("client not authenticated yet! - closing session")
			return
		}
		go func() {
			defer stream.Close()
			socks5Srv.ServeConn(stream)
		}()
	}
}

func (s *serverSession) Close() error {
	s.log("connection closed")
	return s.session.Close()
}

func (s *serverSession) auth(user, pw string) (string, bool) {
	s.authenticated = s.srv.auth.Valid(user, pw)
	if s.authenticated {
		s.log("auth successful")
	} else {
		s.log("auth failed - closing session")
		go func() {
			time.Sleep(time.Second)
			s.session.Close()
		}()
	}
	return s.id, s.authenticated
}

// Allow implements socks5.RuleSet
func (s *serverSession) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	go s.filterLog(req.DestAddr.String())
	return ctx, !isPrivateIP(req.DestAddr.IP)
}

// Resolve implements socks5.NameResolver
func (s *serverSession) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ip, err := s.resolve(name)
	go s.filterLog("DNS: ", name, " -> ", ip)
	return ctx, ip, err
}

func (s *serverSession) resolve(name string) (net.IP, error) {
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

func (s *serverSession) log(a ...interface{}) {
	s.srv.Logger.Printf("[%s] %s", s.id, fmt.Sprint(a...))
}

func (s *serverSession) filterLog(a ...interface{}) {
	s.logFilterMtx.Lock()
	defer s.logFilterMtx.Unlock()

	if s.logFilter == nil {
		s.logFilter = make(map[string]bool)
	}

	reqStr := fmt.Sprint(a...)
	if !s.logFilter[reqStr] {
		s.logFilter[reqStr] = true
		s.srv.Logger.Printf("[%s] %s", s.id, reqStr)
		go func() {
			<-time.NewTimer(time.Minute * 5).C
			s.logFilterMtx.Lock()
			defer s.logFilterMtx.Unlock()
			delete(s.logFilter, reqStr)
		}()
	}
}
