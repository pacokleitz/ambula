package network

import (
	"bytes"
	"fmt"
	"net"
	"sync"
)

const CONSUME_CHAN_SIZE = 1024

type LocalTransport struct {
	addr      net.Addr
	peers     map[net.Addr]*LocalTransport
	consumeCh chan RPC
	lock      sync.RWMutex
}

func NewLocalTransport(addr net.Addr) *LocalTransport {
	return &LocalTransport{
		addr:      addr,
		peers:     make(map[net.Addr]*LocalTransport),
		consumeCh: make(chan RPC, CONSUME_CHAN_SIZE),
	}
}

func (t *LocalTransport) Consume() <-chan RPC {
	return t.consumeCh
}

func (t *LocalTransport) Connect(tr Transport) error {
	ltr := tr.(*LocalTransport)
	t.lock.Lock()
	defer t.lock.Unlock()

	t.peers[tr.Addr()] = ltr

	return nil
}

func (t *LocalTransport) SendMessage(to net.Addr, payload []byte) error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.addr == to {
		return nil
	}

	peer, ok := t.peers[to]
	if !ok {
		return fmt.Errorf("%s: could not send message to unknown peer %s", t.addr, to)
	}

	peer.consumeCh <- RPC{
		From:    t.addr,
		Payload: bytes.NewReader(payload),
	}

	return nil
}

func (t *LocalTransport) Broadcast(payload []byte) error {
	for _, peer := range t.peers {
		if err := t.SendMessage(peer.Addr(), payload); err != nil {
			return err
		}
	}
	return nil
}

func (t *LocalTransport) Addr() net.Addr {
	return t.addr
}
