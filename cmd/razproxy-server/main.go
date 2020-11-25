package main

import (
	"flag"
	"log"
	"os"

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
	LAN         bool
)

func init() {
	flag.StringVar(&ServerAddr, "addr", ":9820", "Server address")
	flag.StringVar(&CertFile, "cert", "", "TLS cert file path")
	flag.StringVar(&KeyFile, "key", "", "TLS key file path")
	flag.StringVar(&User, "user", "", "Username for auth")
	flag.StringVar(&Password, "pw", "", "Password for auth")
	flag.StringVar(&ExternalDNS, "dns", "", "External DNS address")
	flag.BoolVar(&LAN, "lan", false, "Enable requests towards LAN and localhost IP address range")
	flag.Parse()
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	var auth razproxy.Authenticator
	if len(User) > 0 {
		auth = razproxy.BasicAuthenticator{User: Password}
	}

	var certLoader razproxy.CertLoader
	if len(CertFile) > 0 {
		var err error
		certLoader, err = razproxy.NewFileCertLoader(CertFile, KeyFile, logger)
		if err != nil {
			log.Fatal(err)
		}
	}

	srv, err := razproxy.NewServer(auth, certLoader, logger)
	if err != nil {
		log.Fatal(err)
	}

	srv.ExternalDNS = ExternalDNS
	srv.LAN = LAN

	if err := srv.ListenAndServe(ServerAddr); err != nil {
		log.Fatal(err)
	}
}
