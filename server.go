package razproxy

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"golang.org/x/time/rate"
)

// Server ...
type Server struct {
	auth        Authenticator
	tlsConf     *tls.Config
	rate        *rateLimiter
	Logger      *log.Logger
	ExternalDNS string
	LAN         bool
}

// NewServer returns a new Server
func NewServer(auth Authenticator, certLoader CertLoader, logger *log.Logger) (*Server, error) {
	if auth == nil {
		auth = &NilAuthenticator{}
	}
	if certLoader == nil {
		var err error
		certLoader, err = NewGeneratedCertLoader("razproxy", "")
		if err != nil {
			return nil, err
		}
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
		GetCertificate: certLoader.GetCertificate,
	}

	return &Server{
		auth:    auth,
		tlsConf: tlsConf,
		rate:    newRateLimiter(rate.Every(time.Minute), 3),
		Logger:  logger,
	}, nil
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

		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.rate.get(ip).Allow() {
			s.Logger.Println("rate limit exceeded for IP:", ip)
			conn.Close()
			continue
		}

		session, err := s.newSession(conn)
		if err != nil {
			s.Logger.Println("smux error:", err)
			continue
		}
		go session.run()
	}
}
