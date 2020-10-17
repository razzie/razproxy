package razproxy

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-socks5"
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
	session      *ClientSession
	reconnecting bool
	Logger       *log.Logger
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
		Logger:     log.New(os.Stdout, "", log.LstdFlags),
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
	session, err := c.newSession()
	if err != nil {
		if _, certErr := err.(x509.UnknownAuthorityError); !certErr || c.conf.PromptSkipCertVerify == nil {
			return err
		}
		cont := c.conf.PromptSkipCertVerify()
		if cont {
			c.conf.SkipCertVerify = true
			session, err = c.newSession()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	c.session = session
	c.Logger.Println("connected")
	return nil
}

// Dial ...
func (c *Client) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	conn, err := c.session.Dial(ctx, network, addr)
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

		if err, ok := err.(*net.OpError); ok && err.Op == "socks connect" {
			c.Logger.Println("socks connection error - probably incorrect user/password")
		}

		c.session.Close()
		c.Logger.Println("disconnected")
		c.reconnecting = true

		go func() {
			for {
				<-time.NewTimer(time.Second).C
				c.Logger.Println("reconnecting..")
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

	return c.session.Close()
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
			c.Logger.Println(err)
			continue
		}
		go c.socks5Srv.ServeConn(conn)
	}
}
