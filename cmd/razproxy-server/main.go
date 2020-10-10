package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/armon/go-socks5"
	"github.com/xtaci/smux"
)

// command line args
var (
	ServerAddr string
	CertFile   string
	KeyFile    string
	User       string
	Password   string
)

func init() {
	flag.StringVar(&ServerAddr, "addr", ":9820", "Server address")
	flag.StringVar(&CertFile, "cert", "", "TLS cert file path")
	flag.StringVar(&KeyFile, "key", "", "TLS key file path")
	flag.StringVar(&User, "user", "", "Username for auth (optional)")
	flag.StringVar(&Password, "pw", "", "Password for auth (optional)")
	flag.Parse()

	log.SetOutput(os.Stdout)
}

func getCert() (*tls.Certificate, error) {
	if len(CertFile) > 0 {
		if len(KeyFile) == 0 {
			return LoadCertficateAndKeyFromFile(CertFile)
		}
		return GenerateCertificate("razproxy", "")
	}
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	return &cert, err
}

func handleSession(server *socks5.Server, session *smux.Session) {
	defer session.Close()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}
		go func() {
			defer stream.Close()
			server.ServeConn(stream)
		}()
	}
}

func main() {
	rh := &requestHandler{}
	conf := &socks5.Config{
		Resolver: rh,
		Rules:    rh,
		Logger:   log.New(ioutil.Discard, "", 0),
	}
	if len(User) > 0 {
		conf.Credentials = authenticator{User: Password}
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	cer, err := getCert()
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{*cer}}
	ln, err := tls.Listen("tcp", ServerAddr, config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		session, err := smux.Server(conn, nil)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println(conn.RemoteAddr(), "connected")
		go handleSession(server, session)
	}
}
