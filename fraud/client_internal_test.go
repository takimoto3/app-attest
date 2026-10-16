package fraud

import "testing"

func MaxResponseBodySize() int64 {
	return maxResponseBodySize
}

func (c *Client) SetEndpointForTest(u string) { c.endpoint = u }
func (c *Client) EndpointForTest() string     { return c.endpoint }
func (c *Client) RespBodyLimitForTest() int64 { return c.respBodyLimit }

func TestTruncate(t *testing.T) {
	tests := map[string]struct {
		in   string
		n    uint
		want string
	}{
		"short":               {in: "abc", n: 5, want: "abc"},
		"exact":               {in: "abcde", n: 5, want: "abcde"},
		"cut":                 {in: "abcdef", n: 5, want: "abcde..."},
		"multibyte, mid-rune": {in: "あいう", n: 4, want: "あ..."},
		"multibyte, boundary": {in: "あいう", n: 6, want: "あい..."},
		"multibyte, fits":     {in: "あいう", n: 9, want: "あいう"},
		"n zero":              {in: "abc", n: 0, want: "..."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := truncate(tt.in, tt.n); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}
