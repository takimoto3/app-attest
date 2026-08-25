package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"testing"
	"unsafe"
)

func TestDecoder_ReadAdditional(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		ai      byte
		want    uint64
		wantLen int
		wantErr error
	}{
		"direct value":   {[]byte{}, 23, 23, 0, nil},
		"uint8":          {[]byte{0x7b}, 24, 123, 1, nil},
		"uint16":         {[]byte{0x01, 0x00}, 25, 256, 2, nil},
		"uint32":         {[]byte{0x00, 0x01, 0x00, 0x00}, 26, 65536, 4, nil},
		"uint64":         {[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 27, 1, 8, nil},
		"uint8 EOF":      {[]byte{}, 24, 0, 0, io.ErrUnexpectedEOF},
		"uint16 EOF":     {[]byte{0x01}, 25, 0, 0, ErrTooLarge},
		"uint32 EOF":     {[]byte{0x01, 0x02, 0x03}, 26, 0, 0, ErrTooLarge},
		"uint64 EOF":     {[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 27, 0, 0, ErrTooLarge},
		"unsupported 28": {[]byte{}, 28, 0, 0, ErrUnsupportedAdditionalInfo},
		"unsupported 29": {[]byte{}, 29, 0, 0, ErrUnsupportedAdditionalInfo},
		"unsupported 30": {[]byte{}, 30, 0, 0, ErrUnsupportedAdditionalInfo},
		"unsupported 31": {[]byte{}, 31, 0, 0, ErrUnsupportedAdditionalInfo},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(tt.data)

			got, err := d.ReadAdditional(tt.ai)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadAdditional() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ReadAdditional() = %d, want %d", got, tt.want)
			}
			if got := d.pos; got != tt.wantLen {
				t.Fatalf("pos = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestDecodeInt(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    int64
		wantErr error
	}{
		"uint small":     {[]byte{0x00}, 0, nil},                // 0
		"uint 10":        {[]byte{0x0a}, 10, nil},               // 10
		"uint 24":        {[]byte{0x18, 0x18}, 24, nil},         // ai=24, 1バイト
		"uint 300":       {[]byte{0x19, 0x01, 0x2c}, 300, nil},  // ai=25, 2バイト
		"neg small":      {[]byte{0x20}, -1, nil},               // -1
		"neg 10":         {[]byte{0x29}, -10, nil},              // -10
		"neg 300":        {[]byte{0x39, 0x01, 0x2c}, -301, nil}, // -301
		"uint max int64": {[]byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64, nil},
		"uint overflow":  {[]byte{0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, ErrIntegerOverflow},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(tt.data)
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}
			val, err := dec.ReadInt(mt, ai)
			if err != tt.wantErr {
				t.Fatalf("readInt error: %v", err)
			}

			if val != tt.want {
				t.Errorf("got %d, want %d", val, tt.want)
			}
		})
	}
}

func TestDecodeByteString(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want []byte
	}{
		{"short bytes", "43010203", []byte{0x01, 0x02, 0x03}}, // 0x43 → len=3
		{"1 byte len", "581004112233445566778899aabbccddeeff", []byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.hex)
			dec := NewDecoder(data)
			_, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}

			got, err := dec.ReadByteString(ai)
			if err != nil {
				t.Fatalf("DecodeByteString error: %v", err)
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("got %x, want %x", got, tt.want)
			}
		})
	}
}

func TestDecodeTextString(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    string
		wantErr error
	}{
		"short text":    {[]byte{0x63, 'f', 'o', 'o'}, "foo", nil},                   // 0x63 → len=3
		"1 byte len":    {[]byte{0x78, 0x05, 'h', 'e', 'l', 'l', 'o'}, "hello", nil}, // ai=24, 1バイト長
		"invalid UTF-8": {[]byte{0x62, 0xff, 0xfe}, "", ErrInvalidString},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(tt.data)
			_, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}
			got, err := dec.ReadTextString(ai)
			if err != tt.wantErr {
				t.Fatalf("DecodeTextString error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUnsafeTextString(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    string
		wantErr error
	}{
		"short text":    {[]byte{0x63, 'f', 'o', 'o'}, "foo", nil},
		"1 byte len":    {[]byte{0x78, 0x05, 'h', 'e', 'l', 'l', 'o'}, "hello", nil},
		"invalid UTF-8": {[]byte{0x62, 0xff, 0xfe}, "", ErrInvalidString},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(tt.data)
			_, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}

			got, err := dec.ReadUnsafeTextString(ai)
			if err != tt.wantErr {
				t.Fatalf("ReadUnsafeTextString error: %v", err)
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUnsafeTextStringAliasesBuffer(t *testing.T) {
	data := []byte{0x63, 'f', 'o', 'o'}

	dec := NewDecoder(data)
	_, ai, _ := dec.ReadHeader()

	offset := dec.pos

	got, _ := dec.ReadUnsafeTextString(ai)

	if unsafe.StringData(got) != &data[offset] {
		t.Fatal("string does not alias backing buffer")
	}
}

func TestDecoder_Len(t *testing.T) {
	data := []byte{
		0x63, 'f', 'o', 'o', // "foo"
		0x18, 0x7b, // 123
	}

	d := NewDecoder(data)

	if got := d.Len(); got != 6 {
		t.Fatalf("Len() = %d, want 6", got)
	}

	mt, ai, err := d.ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadTextString(ai); err != nil {
		t.Fatal(err)
	}
	if got := d.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	mt, ai, err = d.ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadInt(mt, ai); err != nil {
		t.Fatal(err)
	}
	if got := d.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

var benchIntSmall = []byte{0x0a}             // 10
var benchIntAdd24 = []byte{0x18, 0x64}       // 100
var benchIntAdd25 = []byte{0x19, 0x01, 0x2c} // 300
var benchByteStringHex = "43010203"
var benchByteStringHexLong = "581004112233445566778899aabbccddeeff"
var benchTextData = []byte{0x63, 'f', 'o', 'o'}
var benchTextDataLong = []byte{0x78, 0x0b, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'}

func BenchmarkDecodeIntSmall(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchIntSmall)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}

func BenchmarkDecodeIntAdd24(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchIntAdd24)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}

func BenchmarkDecodeIntAdd25(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchIntAdd25)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}
func BenchmarkDecodeByteString(b *testing.B) {
	data, _ := hex.DecodeString(benchByteStringHex)
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(data)
		mt, ai, _ := dec.ReadHeader()
		if mt != ByteString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		_, _ = dec.ReadByteString(ai)
	}
}

func BenchmarkDecodeByteStringLong(b *testing.B) {
	data, _ := hex.DecodeString(benchByteStringHexLong)
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(data)
		mt, ai, _ := dec.ReadHeader()
		if mt != ByteString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		_, _ = dec.ReadByteString(ai)
	}
}

var sink string

func BenchmarkDecodeTextString(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchTextData)
		mt, ai, _ := dec.ReadHeader()
		if mt != TextString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		sink, _ = dec.ReadTextString(ai)
	}
}

func BenchmarkDecodeTextStringLong(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchTextDataLong)
		mt, ai, _ := dec.ReadHeader()
		if mt != TextString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		sink, _ = dec.ReadTextString(ai)
	}
}

func BenchmarkDecodeUnsafeTextString(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchTextData)
		_, ai, _ := dec.ReadHeader()
		sink, _ = dec.ReadUnsafeTextString(ai)
	}
}

func BenchmarkDecodeUnsafeTextStringLong(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		dec := NewDecoder(benchTextDataLong)
		_, ai, _ := dec.ReadHeader()
		sink, _ = dec.ReadUnsafeTextString(ai)
	}
}
