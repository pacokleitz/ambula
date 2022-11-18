package network

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnect(t *testing.T) {
	aAddr := NetAddr{Addr: "A", Net: "local"}
	bAddr := NetAddr{Addr: "B", Net: "local"}

	ltra := NewLocalTransport(aAddr)
	ltrb := NewLocalTransport(bAddr)

	err := ltra.Connect(ltrb)
	assert.Nil(t, err)

	err = ltrb.Connect(ltra)
	assert.Nil(t, err)

	assert.Equal(t, ltra.peers[ltrb.Addr()], ltrb)
	assert.Equal(t, ltrb.peers[ltra.Addr()], ltra)
}

func TestSendMessage(t *testing.T) {
	aAddr := NetAddr{Addr: "A", Net: "local"}
	bAddr := NetAddr{Addr: "B", Net: "local"}

	ltra := NewLocalTransport(aAddr)
	ltrb := NewLocalTransport(bAddr)

	err := ltra.Connect(ltrb)
	assert.Nil(t, err)

	err = ltrb.Connect(ltra)
	assert.Nil(t, err)

	msg := []byte("hello ambula")
	assert.Nil(t, ltra.SendMessage(ltrb.addr, msg))

	rpc := <-ltrb.Consume()
	assert.Equal(t, rpc.Payload, bytes.NewReader(msg))
	assert.Equal(t, rpc.From, ltra.addr)
}

func TestBroadcast(t *testing.T) {
	aAddr := NetAddr{Addr: "A", Net: "local"}
	bAddr := NetAddr{Addr: "B", Net: "local"}
	cAddr := NetAddr{Addr: "C", Net: "local"}

	ltra := NewLocalTransport(aAddr)
	ltrb := NewLocalTransport(bAddr)
	ltrc := NewLocalTransport(cAddr)

	err := ltra.Connect(ltrb)
	assert.Nil(t, err)

	err = ltra.Connect(ltrc)
	assert.Nil(t, err)

	msg := []byte("hello ambula")
	assert.Nil(t, ltra.Broadcast(msg))

	rpcb := <-ltrb.Consume()
	b, err := io.ReadAll(rpcb.Payload)
	assert.Nil(t, err)
	assert.Equal(t, b, msg)

	rpcC := <-ltrc.Consume()
	b, err = io.ReadAll(rpcC.Payload)
	assert.Nil(t, err)
	assert.Equal(t, b, msg)
}
