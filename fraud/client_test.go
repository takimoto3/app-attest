package fraud_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/takimoto3/app-attest/fraud"
	"github.com/takimoto3/appleapi-core"
)

// mockToken is a fake token provider for testing.
type mockToken struct{}

func (m *mockToken) GetToken(_ time.Time) (string, error) {
	return "dummy", nil
}

func (m *mockToken) SetLogger(l *slog.Logger) {
}

func TestClient_Post(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tests := []struct {
		name       string
		statusCode int
		body       string
		input      []byte
		wantResp   []byte
		wantErr    error
		opts       []appleapi.Option
		wantHost   string
	}{
		{
			name:       "Success Production",
			statusCode: 200,
			body:       base64.StdEncoding.EncodeToString([]byte("receipt")),
			input:      []byte("receipt"),
			wantResp:   []byte("receipt"),
			wantErr:    nil,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "Success Development",
			statusCode: 200,
			body:       base64.StdEncoding.EncodeToString([]byte("receipt")),
			input:      []byte("receipt"),
			wantResp:   []byte("receipt"),
			wantErr:    nil,
			opts:       []appleapi.Option{appleapi.WithDevelopment()},
			wantHost:   fraud.DevelopmentHost,
		},
		{
			name:       "NotModified",
			statusCode: 304,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrNotModified,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "IncorrectEnvironment",
			statusCode: 400,
			body:       "Incorrect Environment",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrIncorrectEnvironment,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "BadPayload",
			statusCode: 400,
			body:       "Bad Payload",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrBadPayload,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "Unauthorized",
			statusCode: 401,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrUnauthorized,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "NoDataFound",
			statusCode: 404,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrNoDataFound,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "TooManyRequests",
			statusCode: 429,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrTooManyRequests,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "ServerError",
			statusCode: 500,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrServerError,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
		{
			name:       "ServiceUnavailable",
			statusCode: 503,
			body:       "",
			input:      []byte("receipt"),
			wantResp:   nil,
			wantErr:    fraud.ErrServiceUnavailable,
			opts:       nil,
			wantHost:   fraud.ProductionHost,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if !bytes.Equal(b, tt.input) {
					t.Errorf("expected request body %q, got %q", tt.input, b)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()
			tt.opts = append(tt.opts, appleapi.WithLogger(logger))

			c, err := fraud.NewClient(&mockToken{}, tt.opts...)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			if c.GetHost() != tt.wantHost {
				t.Errorf("expected Host %q, got %q", tt.wantHost, c.GetHost())
			}

			c.SetHost(server.URL)
			resp, err := c.Do(context.Background(), tt.input)

			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(resp.Receipt, tt.wantResp) {
				t.Errorf("expected receipt %q, got %q", tt.wantResp, resp.Receipt)
			}
		})
	}
}
