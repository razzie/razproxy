package razproxy

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/xtaci/smux"
	"golang.org/x/net/proxy"
)

// ClientSession ...
type ClientSession struct {
	client  *Client
	conn    *tls.Conn
	session *smux.Session
}

func (c *Client) newSession() (*ClientSession, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: c.conf.SkipCertVerify,
	}
	tlsConf.ServerName, _, _ = net.SplitHostPort(c.serverAddr)
	conn, err := tls.Dial("tcp", c.serverAddr, tlsConf)
	if err != nil {
		return nil, err
	}

	session, err := smux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &ClientSession{
		client:  c,
		conn:    conn,
		session: session,
	}, nil
}

// Dial ...
func (s *ClientSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if len(s.client.conf.User) > 0 {
		auth = &proxy.Auth{
			User:     s.client.conf.User,
			Password: s.client.conf.Password,
		}
	}
	dialer, err := proxy.SOCKS5("tcp", s.client.serverAddr, auth, &smuxDialer{session: s.session})
	if err != nil {
		return nil, err
	}

	return dialer.Dial(network, addr)
}

// Close ...
func (s *ClientSession) Close() error {
	s.session.Close()
	return s.conn.Close()
}
