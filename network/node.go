// Package network implements transport and messaging between nodes.
package network

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// TICK_DURATION represents the time in seconds between health-logs
// in the Node main loop.
const TICK_DURATION = 5

// NodeOpts encapsulates the options needed by the Node.
type NodeOpts struct {
	Transports []Transport // Transports that will be connected with the Node
}

// Node is spawning workers and listening for RPCs from multiple Transport.
type Node struct {
	NodeOpts
	rpcCh  chan RPC      // Channel used for incoming RPC from Transports
	quitCh chan struct{} // Channel used for Node shutdown event
}

// NewNode instantiates a Node from a NodeOpts.
func NewNode(opts NodeOpts) *Node {
	return &Node{
		NodeOpts: opts,
		rpcCh:    make(chan RPC),
		quitCh:   make(chan struct{}, 1),
	}
}

// Start starts the main loop of the Node listening for RPCs from the
// Transports and passing them to RPC handlers.
func (n *Node) Start() error {
	n.initTransports()
	ticker := time.NewTicker(TICK_DURATION * time.Second)

free:
	for {
		select {
		case rpc := <-n.rpcCh:
			buf := new(strings.Builder)
			_, err := io.Copy(buf, rpc.Payload)
			if err != nil {
				return err
			}
			fmt.Printf("Peer [%s] sent [%s]\n", rpc.From.String(), buf.String())
		case <-n.quitCh:
			break free
		case <-ticker.C:
			fmt.Println("still running...")
		}
	}

	return nil
}

// initTransports spawns goroutines connecting/listening to Transports
// and passing RPCs back to the Node on reception.
func (n *Node) initTransports() {
	for _, tr := range n.Transports {
		go func(tr Transport) {
			for rpc := range tr.Consume() {
				n.rpcCh <- rpc
			}
		}(tr)
	}
}
