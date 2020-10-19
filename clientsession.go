package razproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/rpc"

	"github.com/xtaci/smux"
)

type clientSession struct {
	id      string
	session *smux.Session
}

func (c *Client) newSession() (s *clientSession, err error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: c.conf.SkipCertVerify,
	}
	tlsConf.ServerName, _, _ = net.SplitHostPort(c.serverAddr)
	conn, err := tls.Dial("tcp", c.serverAddr, tlsConf)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	session, err := smux.Client(conn, nil)
	if err != nil {
		return
	}

	rpcConn, err := session.OpenStream()
	if err != nil {
		return
	}

	rpcClient := rpc.NewClient(rpcConn)
	authReq := &AuthRequest{
		User:     c.conf.User,
		Password: c.conf.Password,
	}
	authRes := new(AuthResult)
	err = rpcClient.Call("RPC.Auth", authReq, authRes)
	if err != nil {
		return
	}
	if !authRes.OK {
		return nil, ErrAuthFailed
	}

	return &clientSession{
		id:      authRes.ID,
		session: session,
	}, nil
}

func (s *clientSession) proxy(conn net.Conn) error {
	stream, err := s.session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	errCh := make(chan error, 2)
	go proxy(stream, conn, errCh)
	go proxy(conn, stream, errCh)
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			if e == io.ErrClosedPipe || e == smux.ErrTimeout {
				continue
			}
			if e, ok := e.(net.Error); ok && e.Timeout() {
				continue
			}
			if e, ok := e.(*net.OpError); ok && e.Source == conn.LocalAddr() {
				continue
			}
			return e
		}
	}
	return nil
}

// Close ...
func (s *clientSession) Close() error {
	return s.session.Close()
}
