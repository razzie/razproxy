package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/armon/go-socks5"
	"github.com/xtaci/smux"
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

	log.SetOutput(os.Stdout)
}

type smuxDialer struct {
	session *smux.Session
}

func newSmuxDialer(conn net.Conn) (*smuxDialer, error) {
	session, err := smux.Client(conn, nil)
	if err != nil {
		return nil, err
	}
	return &smuxDialer{session: session}, nil
}

func (d *smuxDialer) Dial(network, addr string) (net.Conn, error) {
	return d.session.OpenStream()
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
	conn, err := tls.Dial("tcp", ServerAddr, tlsConf)
	if err != nil {
		panic(err)
	}
	smuxDialer, err := newSmuxDialer(conn)
	if err != nil {
		panic(err)
	}
	dialer, err := proxy.SOCKS5("tcp", ServerAddr, auth, smuxDialer)
	if err != nil {
		panic(err)
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		Logger: log.New(ioutil.Discard, "", 0),
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "localhost:"+strconv.Itoa(LocalPort)); err != nil {
		panic(err)
	}
}
