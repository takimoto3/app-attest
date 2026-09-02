package attest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/takimoto3/app-attest/cbor"
)

type item [2][]byte

func sha2(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

func merge(chunks ...[]byte) []byte {
	return bytes.Join(chunks, nil)
}

func cborMap(items ...item) []byte {
	chunks := make([][]byte, 0, 1+len(items)*2)
	chunks = append(chunks, cborHeader(cbor.Map, uint64(len(items))))
	for _, it := range items {
		chunks = append(chunks, it[:]...)
	}
	return bytes.Join(chunks, nil)
}

// cborHeader encodes a CBOR major type + length/value header using the
// shortest applicable encoding (RFC 8949 §3.1). This is a minimal encoder
// used only to build test fixtures; it does not need to support every CBOR
// feature, only what AuthenticatorData / CoseKey Unmarshal consume.
func cborHeader(majorType cbor.MajorType, n uint64) []byte {
	mt := byte(majorType)
	switch {
	case n <= 23:
		return []byte{(mt << 5) | byte(n)}
	case n <= 0xff:
		return []byte{(mt << 5) | 24, byte(n)}
	case n <= 0xffff:
		b := make([]byte, 3)
		b[0] = (mt << 5) | 25
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = (mt << 5) | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = (mt << 5) | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

// cborUint encodes a CBOR unsigned integer (major type 0).
func cborUint(v uint64) []byte {
	return cborHeader(0, v)
}

// cborNegInt encodes a CBOR negative integer (major type 1). v must be < 0.
func cborNegInt(v int64) []byte {
	if v >= 0 {
		panic("cborNegInt: v must be negative")
	}
	return cborHeader(1, uint64(-1-v))
}

// cborBytes encodes a CBOR byte string (major type 2).
func cborBytes(b []byte) []byte {
	return append(cborHeader(2, uint64(len(b))), b...)
}

// cborText encodes a CBOR UTF-8 text string (major type 3).
func cborText(s string) []byte {
	return append(cborHeader(3, uint64(len(s))), []byte(s)...)
}

// cborMapBuilder incrementally builds a CBOR map (major type 5) from
// already-encoded key/value byte pairs, tracking the entry count so the
// map header can be emitted correctly.
type cborMapBuilder struct {
	entries []byte
	count   int
}

func newCBORMap() *cborMapBuilder {
	return &cborMapBuilder{}
}

func (m *cborMapBuilder) add(key, value []byte) *cborMapBuilder {
	m.entries = append(m.entries, key...)
	m.entries = append(m.entries, value...)
	m.count++
	return m
}

func (m *cborMapBuilder) bytes() []byte {
	return append(cborHeader(5, uint64(m.count)), m.entries...)
}

func intPtr(v int) *int          { return &v }
func uint16Ptr(v uint16) *uint16 { return &v }
