package razproxy

import (
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// ErrAuthFailed ...
var ErrAuthFailed = fmt.Errorf("authentication failed")

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
	Logger       *log.Logger
	session      *clientSession
	reconnecting int32 //bool
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
	atomic.StoreInt32(&c.reconnecting, 0)
	c.Logger.Println("connected as", session.id)
	return nil
}

func (c *Client) proxy(conn net.Conn) error {
	for atomic.LoadInt32(&c.reconnecting) != 0 {
		time.Sleep(time.Second)
	}

	err := c.session.proxy(conn)
	if err != nil {
		c.Logger.Println("proxy error:", err)
		if err == ErrAuthFailed || !atomic.CompareAndSwapInt32(&c.reconnecting, 0, 1) {
			return err
		}
		c.session.Close()
		c.Logger.Println("disconnected")
		go func() {
			for {
				time.Sleep(time.Second)
				c.Logger.Println("reconnecting..")
				if err := c.connect(); err == nil {
					return
				}
			}
		}()
	}
	return err
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
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Time{})
			if err := c.proxy(conn); err != nil {
				c.Logger.Println("proxy error:", err)
			}
		}()
	}
}
