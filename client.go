package razproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

// ClientConfig ...
type ClientConfig struct {
	User                 string
	Password             string
	SkipCertVerify       bool
	PromptSkipCertVerify func() bool
}

// Client ...
type Client struct {
	serverAddr string
	conf       *ClientConfig
	conn       *tls.Conn
	dialer     proxy.Dialer
	socks5Srv  *socks5.Server
}

// NewClient returns a new Client
func NewClient(serverAddr string, conf *ClientConfig) (*Client, error) {
	if _, port, _ := net.SplitHostPort(serverAddr); len(port) == 0 {
		serverAddr += ":9820"
	}

	if conf == nil {
		conf = &ClientConfig{}
	}

	c := &Client{
		serverAddr: serverAddr,
		conf:       conf,
	}
	err := c.connect()
	if err != nil {
		return nil, err
	}

	socks5Conf := &socks5.Config{
		Resolver: &fakeDNS{},
		Dial:     c.Dial,
		Logger:   log.New(ioutil.Discard, "", 0),
	}
	c.socks5Srv, err = socks5.New(socks5Conf)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) connect() error {
	tlsConf := &tls.Config{
		ServerName:         c.serverAddr,
		InsecureSkipVerify: c.conf.SkipCertVerify,
	}
	conn, err := tls.Dial("tcp", c.serverAddr, tlsConf)
	if err != nil {
		if _, certErr := err.(x509.UnknownAuthorityError); !certErr || c.conf.PromptSkipCertVerify == nil {
			return err
		}
		cont := c.conf.PromptSkipCertVerify()
		if cont {
			c.conf.SkipCertVerify = true
			tlsConf.InsecureSkipVerify = true
			conn, err = tls.Dial("tcp", c.serverAddr, tlsConf)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	smuxDialer, err := newSmuxDialer(autoReconnect(conn, tlsConf))
	if err != nil {
		conn.Close()
		return err
	}

	var auth *proxy.Auth
	if len(c.conf.User) > 0 {
		auth = &proxy.Auth{
			User:     c.conf.User,
			Password: c.conf.Password,
		}
	}
	socks5Dialer, err := proxy.SOCKS5("tcp", c.serverAddr, auth, smuxDialer)
	if err != nil {
		conn.Close()
		return err
	}

	c.conn = conn
	c.dialer = socks5Dialer
	return nil
}

// Dial ...
func (c *Client) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dialer.Dial(network, addr)
}

// Close closes the connection to the server
func (c *Client) Close() error {
	return c.conn.Close()
}

// ListenAndServe opens a local SOCKS5 port that listens to and transmits requests to the server
func (c *Client) ListenAndServe(port uint16) error {
	l, err := net.Listen("tcp", "localhost:"+strconv.Itoa(int(port)))
	if err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go c.socks5Srv.ServeConn(conn)
	}
	return nil
}
