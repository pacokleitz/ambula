package network

import (
	"bytes"
	"fmt"
	"net"
	"sync"
)

const RPC_CHAN_SIZE = 1024

type LocalTransport struct {
	addr  net.Addr
	peers map[net.Addr]*LocalTransport
	rpcCh chan RPC
	lock  sync.RWMutex
}

func NewLocalTransport(addr net.Addr) *LocalTransport {
	return &LocalTransport{
		addr:  addr,
		peers: make(map[net.Addr]*LocalTransport),
		rpcCh: make(chan RPC, RPC_CHAN_SIZE),
	}
}

func (tr *LocalTransport) Consume() <-chan RPC {
	return tr.rpcCh
}

func (tr *LocalTransport) Connect(peerTr Transport) error {
	localPeerTr := peerTr.(*LocalTransport)
	tr.lock.Lock()
	defer tr.lock.Unlock()

	tr.peers[peerTr.Addr()] = localPeerTr

	return nil
}

func (tr *LocalTransport) SendMessage(to net.Addr, payload []byte) error {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	if tr.addr == to {
		return nil
	}

	peerTr, ok := tr.peers[to]
	if !ok {
		return fmt.Errorf("Transport %s on %s network could not find peer %s.", tr.Addr().String(), tr.Addr().Network(), to)
	}

	peerTr.rpcCh <- RPC{
		From:    tr.addr,
		Payload: bytes.NewReader(payload),
	}

	return nil
}

func (tr *LocalTransport) Broadcast(payload []byte) error {
	for _, peer := range tr.peers {
		if err := tr.SendMessage(peer.Addr(), payload); err != nil {
			return err
		}
	}
	return nil
}

func (tr *LocalTransport) Addr() net.Addr {
	return tr.addr
}
