package razproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

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
	serverAddr   string
	conf         *ClientConfig
	socks5Srv    *socks5.Server
	mtx          sync.Mutex
	conn         *tls.Conn
	dialer       proxy.Dialer
	reconnecting bool
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
		InsecureSkipVerify: c.conf.SkipCertVerify,
	}
	tlsConf.ServerName, _, _ = net.SplitHostPort(c.serverAddr)
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

	smuxDialer, err := newSmuxDialer(conn)
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
	c.mtx.Lock()
	defer c.mtx.Unlock()

	conn, err := c.dialer.Dial(network, addr)
	if err, ok := err.(net.Error); !c.reconnecting && ok && !err.Temporary() {
		reconnect := func() error {
			c.mtx.Lock()
			defer c.mtx.Unlock()
			if err := c.connect(); err != nil {
				return err
			}
			c.reconnecting = false
			return nil
		}

		c.reconnecting = true
		go func() {
			for {
				<-time.NewTimer(time.Second).C
				if err := reconnect(); err == nil {
					return
				}
			}
		}()
	}
	return conn, err
}

// Close closes the connection to the server
func (c *Client) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

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
