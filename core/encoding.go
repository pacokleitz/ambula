package core

import (
	"encoding/gob"
	"io"
)

// An Encoder is used to encode objects of type T.
type Encoder[T any] interface {
	Encode(T) error
}

// A Decoder is used to decode objects of type T.
type Decoder[T any] interface {
	Decode(T) error
}

// GobTxEncoder implements Encoder for Transaction using encoding/gob.
type GobTxEncoder struct {
	w io.Writer
}

// NewGobTxEncoder returns a pointer to a GobTxEncoder given an io.Writer.
func NewGobTxEncoder(w io.Writer) *GobTxEncoder {
	return &GobTxEncoder{
		w: w,
	}
}

// Encode writes the gob encoding of Transaction in the io.Writer w.
func (e *GobTxEncoder) Encode(tx *Transaction) error {
	return gob.NewEncoder(e.w).Encode(tx)
}

// GobTxDecoder implements Decoder for Transaction using encoding/gob.
type GobTxDecoder struct {
	r io.Reader
}

// NewGobTxDecoder returns a pointer to a GobTxDecoder given an io.Reader.
func NewGobTxDecoder(r io.Reader) *GobTxDecoder {
	return &GobTxDecoder{
		r: r,
	}
}

// Decode reads the gob encoding in io.Reader r in Transaction tx.
func (e *GobTxDecoder) Decode(tx *Transaction) error {
	return gob.NewDecoder(e.r).Decode(tx)
}

// GobTxEncoder implements Encoder for Block using encoding/gob.
type GobBlockEncoder struct {
	w io.Writer
}

// NewGobBlockEncoder returns a pointer to a GobBlockEncoder given an io.Writer.
func NewGobBlockEncoder(w io.Writer) *GobBlockEncoder {
	return &GobBlockEncoder{
		w: w,
	}
}

// Encode writes the gob encoding of Block b in the io.Writer w.
func (enc *GobBlockEncoder) Encode(b *Block) error {
	return gob.NewEncoder(enc.w).Encode(b)
}

// GobBlockDecoder implements Decoder for Block using encoding/gob.
type GobBlockDecoder struct {
	r io.Reader
}

// NewGobBlockDecoder returns a pointer to a GobBlockDecoder given an io.Reader.
func NewGobBlockDecoder(r io.Reader) *GobBlockDecoder {
	return &GobBlockDecoder{
		r: r,
	}
}

// Decode reads the gob encoding in io.Reader r in Block b.
func (dec *GobBlockDecoder) Decode(b *Block) error {
	return gob.NewDecoder(dec.r).Decode(b)
}
