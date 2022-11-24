package network

import (
	"io"
	"net"
)

// A MessageType is a single byte representing a message type.
type MessageType byte

const (
	MessageTypeTx            MessageType = 0x1 // Transaction MessageType
	MessageTypeBlock         MessageType = 0x2 // Block MessageType
	MessageTypeBlockRequest  MessageType = 0x3 // Block Request MessageType
	MessageTypeStatus        MessageType = 0x4 // Node Status MessageType
	MessageTypeStatusRequest MessageType = 0x5 // Node Status Request MessageType
	MessageTypeBlocks        MessageType = 0x6 // Batch Block MessageType
)

// A RPC is transmitted over Tranports.
type RPC struct {
	From    net.Addr
	Payload io.Reader
}

// A Message is contained in RPC Payloads.
type Message struct {
	Header MessageType
	Data   []byte
}
