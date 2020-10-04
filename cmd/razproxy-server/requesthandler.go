package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/armon/go-socks5"
)

type requestHandler struct {
	mtx          sync.Mutex
	reqLogFilter map[string]bool
}

func (rh *requestHandler) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	go rh.logRequest(req)
	return ctx, true
}

func (rh *requestHandler) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Println("DNS request:", name)
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}

func (rh *requestHandler) logRequest(req *socks5.Request) {
	rh.mtx.Lock()
	defer rh.mtx.Unlock()

	if rh.reqLogFilter == nil {
		rh.reqLogFilter = make(map[string]bool)
	}

	reqStr := fmt.Sprint(req.RemoteAddr.String(), "->", req.DestAddr.String())
	if !rh.reqLogFilter[reqStr] {
		rh.reqLogFilter[reqStr] = true
		log.Println(reqStr)
		go func() {
			<-time.NewTimer(time.Minute * 5).C
			rh.mtx.Lock()
			defer rh.mtx.Unlock()
			delete(rh.reqLogFilter, reqStr)
		}()
	}
}