package razproxy

import (
	"crypto/tls"
	"log"
	"os"
)

// Server ...
type Server struct {
	auth        Authenticator
	tlsConf     *tls.Config
	Logger      *log.Logger
	ExternalDNS string
}

// NewServer returns a new Server
func NewServer(auth Authenticator, certs ...tls.Certificate) (*Server, error) {
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

	return &Server{
		auth:    auth,
		tlsConf: tlsConf,
		Logger:  log.New(os.Stdout, "", log.LstdFlags),
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
		session, err := s.newSession(conn)
		if err != nil {
			s.Logger.Println("smux error:", err)
			continue
		}
		go session.run()
	}
}
