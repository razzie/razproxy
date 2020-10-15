package razproxy

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"

	"github.com/armon/go-socks5"
	"github.com/xtaci/smux"
)

// Server ...
type Server struct {
	socks5Conf  *socks5.Config
	socks5Srv   *socks5.Server
	tlsConf     *tls.Config
	Logger      *log.Logger
	ExternalDNS string
}

// NewServer returns a new Server
func NewServer(auth Authenticator, certs ...tls.Certificate) (*Server, error) {
	rh := &requestHandler{}
	socks5Conf := &socks5.Config{
		Credentials: auth,
		Resolver:    rh,
		Rules:       rh,
		Logger:      log.New(ioutil.Discard, "", 0),
	}
	socks5Srv, err := socks5.New(socks5Conf)
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: certs,
	}

	srv := &Server{
		socks5Conf: socks5Conf,
		socks5Srv:  socks5Srv,
		tlsConf:    tlsConf,
		Logger:     log.New(os.Stdout, "", log.LstdFlags),
	}
	rh.srv = srv
	return srv, nil
}

// ListenAndServe starts listening and serving requests on a given network address
func (s *Server) ListenAndServe(address string) error {
	ln, err := tls.Listen("tcp", address, s.tlsConf)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.Logger.Println("connection accept error:", err)
			continue
		}
		session, err := smux.Server(conn, nil)
		if err != nil {
			s.Logger.Println("smux error:", err)
			continue
		}
		s.Logger.Println(conn.RemoteAddr(), "connected")
		go s.handleSession(session)
	}
}

func (s *Server) handleSession(session *smux.Session) {
	defer session.Close()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			s.Logger.Println("stream error:", err)
			return
		}
		go func() {
			defer stream.Close()
			s.socks5Srv.ServeConn(stream)
		}()
	}
}
