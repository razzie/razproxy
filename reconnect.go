package razproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type reconnector struct {
	mtx        sync.RWMutex
	localAddr  net.Addr
	remoteAddr net.Addr
	conn       *tls.Conn
	conf       *tls.Config
}

func (c *reconnector) Read(p []byte) (int, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	if c.conn != nil {
		n, err := c.conn.Read(p)
		if _, ok := err.(net.Error); ok {
			go c.retry(true)
		}
		return n, err
	}
	return 0, nil
}

func (c *reconnector) Write(p []byte) (int, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	if c.conn != nil {
		n, err := c.conn.Write(p)
		if _, ok := err.(net.Error); ok {
			go c.retry(true)
		}
		return n, err
	}
	return 0, nil
}

func (c *reconnector) Close() error {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *reconnector) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *reconnector) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *reconnector) retry(first bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if first && c.conn == nil {
		return
	}

	c.conn = nil
	go func() {
		<-time.NewTimer(time.Second).C

		c.mtx.Lock()
		defer c.mtx.Unlock()

		conn, err := tls.Dial(c.remoteAddr.Network(), c.remoteAddr.String(), c.conf)
		if err != nil {
			go c.retry(false)
			return
		}

		c.conn = conn
		fmt.Println("Reconnected")
	}()
}

func autoReconnect(conn *tls.Conn, conf *tls.Config) io.ReadWriteCloser {
	return &reconnector{
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
		conn:       conn,
		conf:       conf,
	}
}
