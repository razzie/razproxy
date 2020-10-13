package razproxy

import (
	"io"
	"net"
	"sync"

	"github.com/xtaci/smux"
)

type smuxDialer struct {
	mtx     sync.Mutex
	conn    io.ReadWriteCloser
	session *smux.Session
}

func newSmuxDialer(conn io.ReadWriteCloser) (*smuxDialer, error) {
	session, err := smux.Client(conn, nil)
	if err != nil {
		return nil, err
	}
	return &smuxDialer{
		conn:    conn,
		session: session,
	}, nil
}

func (d *smuxDialer) Dial(network, addr string) (net.Conn, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.session == nil {
		s, err := smux.Client(d.conn, nil)
		if err != nil {
			return nil, err
		}
		d.session = s
	}

	conn, err := d.session.OpenStream()
	if _, ok := err.(net.Error); ok {
		d.session = nil
	}
	return conn, err
}
