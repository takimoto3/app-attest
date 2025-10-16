package cbor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecodeInt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int64
	}{
		{"uint small", []byte{0x00}, 0},             // 0
		{"uint 10", []byte{0x0a}, 10},               // 10
		{"uint 24", []byte{0x18, 0x18}, 24},         // ai=24, 1バイト
		{"uint 300", []byte{0x19, 0x01, 0x2c}, 300}, // ai=25, 2バイト
		{"neg small", []byte{0x20}, -1},             // -1
		{"neg 10", []byte{0x29}, -10},               // -10
		{"neg 300", []byte{0x39, 0x01, 0x2c}, -301}, // -301
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewDecoder(tt.data)
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}
			val, err := dec.ReadInt(mt, ai)
			if err != nil {
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
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"short text", []byte{0x63, 'f', 'o', 'o'}, "foo"},                   // 0x63 → len=3
		{"1 byte len", []byte{0x78, 0x05, 'h', 'e', 'l', 'l', 'o'}, "hello"}, // ai=24, 1バイト長
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewDecoder(tt.data)
			_, ai, err := dec.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader error: %v", err)
			}
			got, err := dec.ReadTextString(ai)
			if err != nil {
				t.Fatalf("DecodeTextString error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
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
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(benchIntSmall)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}

func BenchmarkDecodeIntAdd24(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(benchIntAdd24)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}

func BenchmarkDecodeIntAdd25(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(benchIntAdd25)
		mt, ai, _ := dec.ReadHeader()
		_, _ = dec.ReadInt(mt, ai)
	}
}
func BenchmarkDecodeByteString(b *testing.B) {
	data, _ := hex.DecodeString(benchByteStringHex)
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(data)
		mt, ai, _ := dec.ReadHeader()
		if mt != ByteString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		_, _ = dec.ReadByteString(ai)
	}
}

func BenchmarkDecodeTextString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(benchTextData)
		mt, ai, _ := dec.ReadHeader()
		if mt != TextString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		_, _ = dec.ReadTextString(ai)
	}
}

func BenchmarkDecodeTextStringLong(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(benchTextDataLong)
		mt, ai, _ := dec.ReadHeader()
		if mt != TextString {
			b.Fatalf("unexpected major type: %d", mt)
		}
		_, _ = dec.ReadTextString(ai)
	}
}
