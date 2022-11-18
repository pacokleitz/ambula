package network

import (
	"fmt"
	"io"
	"strings"
	"time"
)

const TICK_DURATION = 5

type ServerOpts struct {
	Transports []Transport
}

type Server struct {
	ServerOpts
	rpcCh  chan RPC
	quitCh chan struct{}
}

func NewServer(opts ServerOpts) *Server {
	return &Server{
		ServerOpts: opts,
		rpcCh:      make(chan RPC),
		quitCh:     make(chan struct{}, 1),
	}
}

func (s *Server) Start() error {
	s.initTransports()
	ticker := time.NewTicker(TICK_DURATION * time.Second)

free:
	for {
		select {
		case rpc := <-s.rpcCh:
			buf := new(strings.Builder)
			_, err := io.Copy(buf, rpc.Payload)
			if err != nil {
				return err
			}
			fmt.Printf("%s sent \"%s\"\n", rpc.From.String(), buf.String())
		case <-s.quitCh:
			break free
		case <-ticker.C:
			fmt.Printf("do stuff every %d seconds\n", TICK_DURATION)
		}
	}

	fmt.Println("Server shutdown")
	return nil
}

func (s *Server) initTransports() {
	for _, tr := range s.Transports {
		go func(tr Transport) {
			for rpc := range tr.Consume() {
				s.rpcCh <- rpc
			}
		}(tr)
	}
}
