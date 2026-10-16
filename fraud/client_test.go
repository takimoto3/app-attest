package fraud_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/takimoto3/app-attest/fraud"
	"github.com/takimoto3/appleapi-core"
)

type mockToken struct{}

func (*mockToken) GetToken(time.Time) (string, error) { return "dummy", nil }
func (*mockToken) SetLogger(*slog.Logger)             {}

var quiet = appleapi.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...any) (*fraud.Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	c, err := fraud.NewClient(&mockToken{}, append([]any{quiet}, opts...)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.SetEndpointForTest(srv.URL + fraud.Path)
	return c, &hits
}

func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestNewClient(t *testing.T) {
	tests := map[string]struct {
		opts         []any
		wantEndpoint string
		wantLimit    int64
		wantErr      *wantError
	}{
		"no options -> production": {
			wantEndpoint: fraud.ProductionHost + fraud.Path,
			wantLimit:    1 << 20},
		"appleapi.WithDevelopment -> development": {
			opts:         []any{appleapi.WithDevelopment()},
			wantEndpoint: fraud.DevelopmentHost + fraud.Path,
			wantLimit:    1 << 20},
		"WithResponseBodyLimit": {
			opts:         []any{fraud.WithResponseBodyLimit(10)},
			wantEndpoint: fraud.ProductionHost + fraud.Path,
			wantLimit:    10},
		"WithResponseBodyLimit(0) is ignored": {
			opts:         []any{fraud.WithResponseBodyLimit(0)},
			wantEndpoint: fraud.ProductionHost + fraud.Path,
			wantLimit:    1 << 20},
		"WithResponseBodyLimit(-1) is ignored": {
			opts:         []any{fraud.WithResponseBodyLimit(-1)},
			wantEndpoint: fraud.ProductionHost + fraud.Path,
			wantLimit:    1 << 20},
		"mixed (order independent)": {
			opts:         []any{fraud.WithResponseBodyLimit(10), appleapi.WithDevelopment()},
			wantEndpoint: fraud.DevelopmentHost + fraud.Path,
			wantLimit:    10},
		"untyped nil": {
			opts:    []any{nil},
			wantErr: expectError("fraud: unsupported option #1 of type <nil>")},
		"typed nil fraud.Option": {
			opts:    []any{fraud.Option(nil)},
			wantErr: expectError("nil option")},
		"unknown type string": {
			opts:    []any{"typo"},
			wantErr: expectError("unsupported option")},
		"unknown type int": {
			opts:    []any{42},
			wantErr: expectError("unsupported option"),
		},
		"MaxInt64 response body limit is ignored": {
			opts:         []any{fraud.WithResponseBodyLimit(math.MaxInt64)},
			wantEndpoint: fraud.ProductionHost + fraud.Path,
			wantLimit:    fraud.MaxResponseBodySize(),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := fraud.NewClient(&mockToken{}, append([]any{quiet}, tt.opts...)...)
			if !assertErr(t, err, tt.wantErr) {
				return
			}
			if got := c.EndpointForTest(); got != tt.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", got, tt.wantEndpoint)
			}
			if got := c.RespBodyLimitForTest(); got != tt.wantLimit {
				t.Errorf("limit = %d, want %d", got, tt.wantLimit)
			}
		})
	}
}

func TestDo_Request(t *testing.T) {
	receipt := []byte("raw-receipt-bytes")
	wantBody := base64.StdEncoding.EncodeToString(receipt)

	c, hits := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != fraud.Path {
			t.Errorf("path = %s, want %s", r.URL.Path, fraud.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dummy" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer dummy")
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != wantBody {
			t.Errorf("body = %q, want %q", b, wantBody)
		}
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("new"))))
	})

	resp, err := c.Do(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.Receipt, []byte("new")) {
		t.Errorf("receipt = %q", resp.Receipt)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestDo_EmptyReceipt_NoRequest(t *testing.T) {
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			c, hits := newTestClient(t, reply(200, "x"))
			if _, err := c.Do(context.Background(), in); err == nil {
				t.Fatal("expected error")
			}
			if hits.Load() != 0 {
				t.Errorf("request must not be sent, hits = %d", hits.Load())
			}
		})
	}
}

func TestDo_Responses(t *testing.T) {
	tests := map[string]struct {
		status  int
		body    string
		want    *fraud.Response
		wantErr *wantError
	}{
		"200 ok": {
			status: 200, body: base64.StdEncoding.EncodeToString([]byte("new")),
			want: &fraud.Response{Receipt: []byte("new")}},
		"200 ok padded": {
			status: 200, body: base64.StdEncoding.EncodeToString([]byte("receipt")),
			want: &fraud.Response{Receipt: []byte("receipt")}},
		"200 newline only": {
			status: 200, body: "\n",
			wantErr: expectError("empty receipt")},
		"304": {status: 304, wantErr: expectError(fraud.ErrNotBeforeDate)},
		"400 incorrect environment": {
			status: 400, body: "Incorrect Environment",
			wantErr: expectError(fraud.ErrIncorrectEnvironment),
		},
		"400 bad payload": {
			status: 400, body: "Bad Payload",
			wantErr: expectError(fraud.ErrBadPayload),
		},
		"400 case-insensitive": {
			status: 400, body: "BAD PAYLOAD",
			wantErr: expectError(fraud.ErrBadPayload),
		},
		"400 unknown body": {
			status: 400, body: "weird",
			wantErr: expectError("bad request (400)"),
		},
		"401": {status: 401, wantErr: expectError(fraud.ErrUnauthorized)},
		"404": {status: 404, wantErr: expectError(fraud.ErrNoDataFound)},
		"418": {
			status: 418, body: "teapot",
			wantErr: expectError("unexpected status code 418"),
		},
		"429":                {status: 429, wantErr: expectError(fraud.ErrTooManyRequests)},
		"500":                {status: 500, wantErr: expectError(fraud.ErrServerError)},
		"503":                {status: 503, wantErr: expectError(fraud.ErrServiceUnavailable)},
		"200 empty body":     {status: 200, wantErr: expectError("empty response body")},
		"200 invalid base64": {status: 200, body: "!!!", wantErr: expectError("decode base64")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, reply(tt.status, tt.body))
			resp, err := c.Do(context.Background(), []byte("r"))
			if !assertErr(t, err, tt.wantErr) {
				if resp != nil {
					t.Errorf("resp must be nil on error")
				}
				return
			}
			if diff := cmp.Diff(tt.want, resp); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDo_BodyLimit(t *testing.T) {
	const limit = 8
	const ok = "AAAAAAAA" // 8 bytes, valid base64 -> 6 zero bytes

	tests := map[string]struct {
		status  int
		body    string
		wantErr *wantError
	}{
		"exactly limit": {status: 200, body: ok},
		"limit+1": {
			status: 200, body: ok + "A",
			wantErr: expectError("exceeds"),
		},
		"trailing newline counts": {
			status: 200, body: ok + "\n",
			wantErr: expectError("exceeds"),
		},
		"error status, oversize": {
			status: 503, body: ok + "A",
			wantErr: expectError("exceeds"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, reply(tt.status, tt.body), fraud.WithResponseBodyLimit(limit))
			resp, err := c.Do(context.Background(), []byte("r"))
			if !assertErr(t, err, tt.wantErr) {
				if resp != nil {
					t.Errorf("resp must be nil on error")
				}
				return
			}
			if len(resp.Receipt) != 6 {
				t.Errorf("len(receipt) = %d, want 6", len(resp.Receipt))
			}
		})
	}
}

func TestDo_ContextCancel(t *testing.T) {
	release := make(chan struct{})
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, []byte("r"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestDo_UnknownBody_Truncated(t *testing.T) {
	c, _ := newTestClient(t, reply(400, strings.Repeat("x", 5000)))
	_, err := c.Do(context.Background(), []byte("r"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasSuffix(err.Error(), "...") {
		t.Errorf("error must be truncated, got len %d", len(err.Error()))
	}
	if len(err.Error()) > 300 {
		t.Errorf("error too long: %d", len(err.Error()))
	}
}

func TestDo_UnexpectedStatus_Truncated(t *testing.T) {
	c, _ := newTestClient(t, reply(502, strings.Repeat("x", 5000)))
	_, err := c.Do(context.Background(), []byte("r"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasSuffix(err.Error(), "...") || len(err.Error()) > 300 {
		t.Errorf("error not truncated: len %d", len(err.Error()))
	}
}
