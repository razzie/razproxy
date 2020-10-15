package main

import (
	"crypto/tls"
	"flag"

	"github.com/razzie/razproxy"
)

// command line args
var (
	ServerAddr  string
	CertFile    string
	KeyFile     string
	User        string
	Password    string
	ExternalDNS string
)

func init() {
	flag.StringVar(&ServerAddr, "addr", ":9820", "Server address")
	flag.StringVar(&CertFile, "cert", "", "TLS cert file path")
	flag.StringVar(&KeyFile, "key", "", "TLS key file path")
	flag.StringVar(&User, "user", "", "Username for auth")
	flag.StringVar(&Password, "pw", "", "Password for auth")
	flag.StringVar(&ExternalDNS, "dns", "", "External DNS address")
	flag.Parse()
}

func getCert() (*tls.Certificate, error) {
	if len(CertFile) > 0 {
		if len(KeyFile) == 0 {
			return razproxy.LoadCertficateAndKeyFromFile(CertFile)
		}
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		return &cert, err
	}
	return razproxy.GenerateCertificate("razproxy", "")
}

func main() {
	cert, err := getCert()
	if err != nil {
		panic(err)
	}

	var auth razproxy.Authenticator
	if len(User) > 0 {
		auth = razproxy.BasicAuthenticator{User: Password}
	}

	srv, err := razproxy.NewServer(auth, *cert)
	srv.ExternalDNS = ExternalDNS
	if err := srv.ListenAndServe(ServerAddr); err != nil {
		panic(err)
	}
}
