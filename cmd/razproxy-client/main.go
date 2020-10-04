package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"strconv"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

// command line args
var (
	ServerAddr    string
	LocalPort     int
	User          string
	Password      string
	SkipTLSVerify bool
)

func init() {
	flag.StringVar(&ServerAddr, "addr", "", "Server address/hostname")
	flag.IntVar(&LocalPort, "port", 1080, "Local SOCKS5 port")
	flag.StringVar(&User, "user", "", "Username for auth")
	flag.StringVar(&Password, "pw", "", "Password for auth")
	flag.BoolVar(&SkipTLSVerify, "skip-tls-verify", false, "Skip TLC cert verification")
	flag.Parse()

	if _, port, _ := net.SplitHostPort(ServerAddr); len(port) == 0 {
		ServerAddr += ":9820"
	}
}

func main() {
	var auth *proxy.Auth
	if len(User) > 0 {
		auth = &proxy.Auth{
			User:     User,
			Password: Password,
		}
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: SkipTLSVerify,
	}
	dialer, err := proxy.SOCKS5("tcp", ServerAddr, auth, &tlsDialer{Config: tlsConf})
	if err != nil {
		panic(err)
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "localhost:"+strconv.Itoa(LocalPort)); err != nil {
		panic(err)
	}
}
