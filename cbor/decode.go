package cbor

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MajorType represents the top 3 bits of a CBOR data item.
// It defines the general category of the encoded value.
type MajorType byte

// CBOR major types as defined by RFC 8949.
const (
	UnsignedInt MajorType = 0 // Unsigned integer
	NegativeInt MajorType = 1 // Negative integer
	ByteString  MajorType = 2 // Byte string (raw binary)
	TextString  MajorType = 3 // Text string (UTF-8)
	Array       MajorType = 4 // Array of elements
	Map         MajorType = 5 // Map of key/value pairs
)

// Decoder is a lightweight, zero-allocation CBOR decoder.
// It reads data directly from a provided byte slice, avoiding intermediate buffers.
// The decoder maintains a read position (`pos`) that advances as data is consumed.
type Decoder struct {
	data []byte // Raw CBOR-encoded input
	pos  int    // Current read offset in `data`
}

// NewDecoder creates a new Decoder instance for the given CBOR-encoded data.
// The provided byte slice is not copied and must remain valid for the lifetime of the Decoder.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data}
}

// readN returns the next n bytes from the input buffer.
// If insufficient data remains, io.ErrUnexpectedEOF is returned.
func (d *Decoder) readN(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, io.ErrUnexpectedEOF
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// ReadHeader reads the next CBOR header byte and returns its major type and additional info.
// The major type indicates the data kind, and the additional info encodes length or value hints.
func (d *Decoder) ReadHeader() (mt MajorType, ai byte, err error) {
	if d.pos >= len(d.data) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b := d.data[d.pos]
	d.pos++
	mt = MajorType(b >> 5) // upper 3 bits
	ai = b & 0x1f          // lower 5 bits
	return
}

// ReadAdditional interprets the additional information (AI) bits from a CBOR header.
// Depending on the AI value, this function reads 0–8 additional bytes to construct an integer.
// Returns the resolved numeric value.
func (d *Decoder) ReadAdditional(ai byte) (uint64, error) {
	switch {
	case ai <= 23:
		return uint64(ai), nil
	case ai == 24:
		if d.pos >= len(d.data) {
			return 0, io.ErrUnexpectedEOF
		}
		v := d.data[d.pos]
		d.pos++
		return uint64(v), nil
	case ai == 25:
		b, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case ai == 26:
		b, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case ai == 27:
		b, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		return 0, fmt.Errorf("unsupported additional info: %d", ai)
	}
}

// ReadInt reads a CBOR integer value (unsigned or negative).
// The caller must pass the major type (0 or 1) and its additional info value.
// Returns the decoded integer as int64.
func (d *Decoder) ReadInt(mt MajorType, ai byte) (int64, error) {
	n, err := d.ReadAdditional(ai)
	if err != nil {
		return 0, err
	}
	switch mt {
	case UnsignedInt:
		return int64(n), nil
	case NegativeInt:
		return -1 - int64(n), nil
	default:
		return 0, fmt.Errorf("expected int type")
	}
}

// ReadByteString reads a CBOR byte string (major type 2).
// The AI value specifies the length or provides information to read it.
// Returns a slice referencing the underlying data without copying.
func (d *Decoder) ReadByteString(ai byte) ([]byte, error) {
	length, err := d.ReadAdditional(ai)
	if err != nil {
		return nil, err
	}
	b, err := d.readN(int(length))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ReadTextString reads a CBOR UTF-8 text string (major type 3).
// Internally, it reuses ReadByteString and converts the result to string.
// Returns a Go string value.
func (d *Decoder) ReadTextString(ai byte) (string, error) {
	b, err := d.ReadByteString(ai)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
