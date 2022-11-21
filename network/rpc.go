package network

import (
	"io"
	"net"
)

type MessageType byte

const (
	MessageTypeTx            MessageType = 0x1
	MessageTypeBlock         MessageType = 0x2
	MessageTypeBlockRequest  MessageType = 0x3
	MessageTypeStatus        MessageType = 0x4
	MessageTypeStatusRequest MessageType = 0x5
	MessageTypeBlocks        MessageType = 0x6
)

type RPC struct {
	From    net.Addr
	Payload io.Reader
}

type Message struct {
	Header MessageType
	Data   []byte
}
