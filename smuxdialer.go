package razproxy

import (
	"net"

	"github.com/xtaci/smux"
)

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
