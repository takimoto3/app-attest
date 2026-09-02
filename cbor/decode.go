package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"
	"unsafe"
)

var (
	ErrTooLarge                  = errors.New("cbor: data length exceeds buffer bounds")
	ErrIntegerOverflow           = errors.New("cbor: integer overflow")
	ErrInvalidString             = errors.New("cbor: invalid UTF-8 text string")
	ErrInvalidIntType            = errors.New("cbor: expected int type")
	ErrUnsupportedAdditionalInfo = errors.New("cbor: unsupported additional info")
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
	Tag         MajorType = 6 // Semantic tag (metadata)
	SimpleFloat MajorType = 7 // Simple values / Floating-point numbers
)

// Decoder is a lightweight, zero-allocation CBOR decoder.
// It reads data directly from a provided byte slice, avoiding intermediate buffers.
// The decoder maintains a read position (`pos`) that advances as data is consumed.
type Decoder struct {
	data []byte // Raw CBOR-encoded input
	pos  int    // Current read offset in `data`
}

// NewDecoder creates a new Decoder instance for the given CBOR-encoded data.
// The provided byte slice is not copied and must remain valid for the
// lifetime of the Decoder (see ReadUnsafeTextString).
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data}
}

// readN returns the next n bytes from the input buffer.
// If insufficient data remains, io.ErrUnexpectedEOF is returned.
func (d *Decoder) readN(n uint64) ([]byte, error) {
	remaining := uint64(len(d.data) - d.pos)
	if n > remaining {
		return nil, ErrTooLarge
	}
	ni := int(n)
	b := d.data[d.pos : d.pos+ni]
	d.pos += ni
	return b, nil
}

// Len returns the number of unread bytes remaining in the input buffer.
func (d *Decoder) Len() int {
	return len(d.data) - d.pos
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
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedAdditionalInfo, ai)
	}
}

// ReadInt reads a CBOR integer value (unsigned or negative).
// The caller must pass the major type (0 or 1) and its additional info value.
// Returns the decoded integer as int64.
func (d *Decoder) ReadInt(mt MajorType, ai byte) (int64, error) {
	if mt == UnsignedInt || mt == NegativeInt {
		n, err := d.ReadAdditional(ai)
		if err != nil {
			return 0, err
		}
		if n > math.MaxInt64 {
			return 0, ErrIntegerOverflow
		}
		switch mt {
		case UnsignedInt:
			return int64(n), nil
		case NegativeInt:
			return -1 - int64(n), nil
		}
	}
	return 0, ErrInvalidIntType
}

// ReadUint32 reads a CBOR unsigned integer value and returns it as uint32.
// Returns ErrIntegerOverflow if the value exceeds math.MaxUint32.
func (d *Decoder) ReadUint32(ai byte) (uint32, error) {
	n, err := d.ReadAdditional(ai)
	if err != nil {
		return 0, err
	}
	if n > math.MaxUint32 {
		return 0, ErrIntegerOverflow
	}
	return uint32(n), nil
}

// ReadByteString reads a CBOR byte string (major type 2).
// The AI value specifies the length or provides information to read it.
// Returns a slice referencing the underlying data without copying.
func (d *Decoder) ReadByteString(ai byte) ([]byte, error) {
	length, err := d.ReadAdditional(ai)
	if err != nil {
		return nil, err
	}
	b, err := d.readN(length)
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
	if !utf8.Valid(b) {
		return "", ErrInvalidString
	}
	return string(b), nil
}

// ReadUnsafeTextString reads a CBOR UTF-8 text string (major type 3).
// The returned string aliases the underlying data and must not outlive it,
// nor should the data be mutated while the string is in use. Use
// ReadTextString if that's a problem.
func (d *Decoder) ReadUnsafeTextString(ai byte) (string, error) {
	b, err := d.ReadByteString(ai)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", ErrInvalidString
	}
	return unsafe.String(unsafe.SliceData(b), len(b)), nil
}
