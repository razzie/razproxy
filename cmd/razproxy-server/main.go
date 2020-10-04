package main

import (
	"crypto/tls"
	"flag"
	"log"

	"github.com/armon/go-socks5"
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
}

func getCert() (tls.Certificate, error) {
	if len(CertFile) == 0 || len(KeyFile) == 0 {
		return tls.X509KeyPair(genTLSCert("razproxy", ""))
	}
	return tls.LoadX509KeyPair(CertFile, KeyFile)
}

func main() {
	conf := &socks5.Config{}
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

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ServerAddr, config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Connection error:", err)
			continue
		}
		go server.ServeConn(conn)
	}
}
