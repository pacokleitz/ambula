package network

import "net"

// The Transport interface exposes the methods needed for
// communication between peers.
type Transport interface {
	Consume() <-chan RPC
	Connect(Transport) error
	SendMessage(net.Addr, []byte) error
	Broadcast([]byte) error
	Addr() net.Addr
}
