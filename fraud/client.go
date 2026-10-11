// Package fraud provides a client for Apple's App Attest
// attestation data verification API.
//
// It allows requesting the attestation receipt and interpreting
// Apple's response according to the App Attest specification.
package fraud

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/takimoto3/appleapi-core"
	"github.com/takimoto3/appleapi-core/token"
)

const (
	// ProductionHost is the endpoint for production App Attest requests.
	ProductionHost = "https://data.appattest.apple.com"

	// DevelopmentHost is the endpoint for development App Attest requests.
	DevelopmentHost = "https://data-development.appattest.apple.com"

	// Path is the fixed path for attestation data API.
	Path = "/v1/attestationData"

	maxResponseBodySize int64 = 1 << 20 // 1MB

	maxErrBodyLen = 200
)

var (
	// ErrNotBeforeDate indicates that the request was made before the previous
	// receipt's "Not Before" date (HTTP 304).
	ErrNotBeforeDate = errors.New("fraud: request made before receipt's not-before date")

	// ErrIncorrectEnvironment indicates that a development receipt was used
	// in production, or vice versa (HTTP 400).
	ErrIncorrectEnvironment = errors.New("fraud: receipt environment does not match request environment")

	// ErrBadPayload indicates that the request has a missing or badly formatted payload (HTTP 400).
	ErrBadPayload = errors.New("fraud: missing or malformed request payload")

	// ErrUnauthorized indicates that the authentication token is invalid or does not match the receipt (HTTP 401).
	ErrUnauthorized = errors.New("fraud: authentication token invalid or does not match receipt")

	// ErrNoDataFound indicates that there is no data available for the supplied receipt (HTTP 404).
	ErrNoDataFound = errors.New("fraud: no data found for supplied receipt")

	// ErrTooManyRequests indicates that the client sent too many requests (HTTP 429).
	ErrTooManyRequests = errors.New("fraud: too many requests")

	// ErrServerError indicates a server-side error occurred (HTTP 500).
	ErrServerError = errors.New("fraud: server error")

	// ErrServiceUnavailable indicates that the service is temporarily unavailable (HTTP 503).
	ErrServiceUnavailable = errors.New("fraud: service unavailable")

	// ErrNotModified is the old name of ErrNotBeforeDate.
	//
	// Deprecated: use ErrNotBeforeDate.
	ErrNotModified = ErrNotBeforeDate
)

type config struct {
	respBodyLimit int64
}

// Option configures the fraud Client. Pass it to NewClient together
// with appleapi.Option values.
type Option func(*config)

// WithResponseBodyLimit sets the maximum accepted response body size in bytes.
// Values <= 0 are ignored.
func WithResponseBodyLimit(n int64) Option {
	return func(c *config) {
		if n > 0 {
			c.respBodyLimit = n
		}
	}
}

// Client provides access to the App Attest attestation data endpoint.
// It wraps appleapi.Client and automatically selects the production or
// development host depending on the client configuration.
type Client struct {
	inner         *appleapi.Client
	endpoint      string
	respBodyLimit int64
}

// Response represents a successful attestation data response from Apple.
// The Receipt field contains the decoded binary receipt.
type Response struct {
	Receipt []byte
}

// NewClient returns a new Client.
//
// opts accepts appleapi.Option (passed to the underlying client) and
// Option (applied to this package's Client).
// Any other type, including nil, results in an error.
func NewClient(tp token.Provider, opts ...any) (*Client, error) {
	return NewClientFromInitializer(appleapi.DefaultHTTPClientInitializer(), tp, opts...)
}

// NewClientFromInitializer returns a new Client instance for the App Attest API
// with a custom HTTPClientInitializer.
// The host is automatically set to the development or production endpoint
// based on the configuration of the underlying appleapi.Client.
func NewClientFromInitializer(initializer appleapi.HTTPClientInitializer, tp token.Provider, opts ...any) (*Client, error) {
	cfg := config{respBodyLimit: maxResponseBodySize}
	var apiOpts []appleapi.Option
	for i, o := range opts {
		switch v := o.(type) {
		case appleapi.Option:
			apiOpts = append(apiOpts, v)
		case Option:
			if v == nil {
				return nil, fmt.Errorf("fraud: nil option #%d", i)
			}
			v(&cfg)
		default:
			return nil, fmt.Errorf("fraud: unsupported option #%d of type %T", i, o)
		}
	}
	c, err := appleapi.NewClient(initializer, ProductionHost, tp, apiOpts...)
	if err != nil {
		return nil, err
	}

	if c.Development {
		c.Host = DevelopmentHost
	}
	endpoint, err := url.JoinPath(c.Host, Path)
	if err != nil {
		return nil, fmt.Errorf("fraud: build endpoint: %w", err)
	}

	return &Client{
		inner:         c,
		endpoint:      endpoint,
		respBodyLimit: cfg.respBodyLimit}, nil
}

// Do sends a base64-encoded attestation receipt to Apple's attestation
// data endpoint and returns the decoded receipt on success.
//
// Possible error values correspond to Apple's documented HTTP status codes:
//
//   - ErrNotBeforeDate (304)
//   - ErrIncorrectEnvironment, ErrBadPayload (400)
//   - ErrUnauthorized (401)
//   - ErrNoDataFound (404)
//   - ErrTooManyRequests (429)
//   - ErrServerError (500)
//   - ErrServiceUnavailable (503)
func (c *Client) Do(ctx context.Context, receipt []byte) (*Response, error) {
	if len(receipt) == 0 {
		return nil, errors.New("fraud: receipt must not be empty")
	}
	body := base64.StdEncoding.AppendEncode(nil, receipt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		c.inner.Logger.Error("failed to create AppAttest request", "error", err)
		return nil, fmt.Errorf("fraud: failed to create request: %w", err)
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		c.inner.Logger.Error("failed to perform AppAttest request", "error", err)
		return nil, fmt.Errorf("fraud: failed to perform attestation request: %w", err)
	}
	defer resp.Body.Close()

	return c.handleResponse(resp)
}

// handleResponse interprets the HTTP response from Apple's App Attest service
// and maps status codes to predefined error values.
func (c *Client) handleResponse(resp *http.Response) (*Response, error) {
	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, c.respBodyLimit+1))
	if err != nil {
		c.inner.Logger.Error("failed to read AppAttest response body",
			"status", resp.StatusCode,
			"error", err,
		)
		return nil, fmt.Errorf("fraud: read response body: %w", err)
	}

	if int64(len(bodyData)) > c.respBodyLimit {
		c.inner.Logger.Error("AppAttest response body too large",
			"status", resp.StatusCode,
			"limit", c.respBodyLimit,
		)
		return nil, fmt.Errorf("fraud: response body exceeds %d bytes", c.respBodyLimit)
	}

	c.inner.Logger.Debug("AppAttest response received",
		"status", resp.StatusCode,
	)

	switch resp.StatusCode {
	case 200:
		if len(bodyData) == 0 {
			return nil, errors.New("fraud: empty response body")
		}
		receipt, err := base64.StdEncoding.AppendDecode(make([]byte, 0, base64.StdEncoding.DecodedLen(len(bodyData))), bodyData)
		if err != nil {
			c.inner.Logger.Warn("invalid base64 in AppAttest response", "error", err)
			return nil, fmt.Errorf("fraud: decode base64 receipt: %w", err)
		}
		if len(receipt) == 0 {
			return nil, errors.New("fraud: empty receipt")
		}
		return &Response{Receipt: receipt}, nil

	case 304:
		c.inner.Logger.Info("AppAttest not before date", "status", 304)
		return nil, ErrNotBeforeDate

	case 400:
		body := string(bodyData)
		lower := strings.ToLower(body)
		switch {
		case strings.Contains(lower, "incorrect environment"):
			c.inner.Logger.Warn("incorrect environment", "status", 400)
			return nil, ErrIncorrectEnvironment
		case strings.Contains(lower, "bad payload"):
			c.inner.Logger.Warn("bad payload", "status", 400)
			return nil, ErrBadPayload
		default:
			truncated := truncate(body, maxErrBodyLen)
			c.inner.Logger.Warn("bad request", "status", 400, "body", truncated)
			return nil, fmt.Errorf("fraud: bad request (400): %s", truncated)
		}

	case 401:
		c.inner.Logger.Warn("unauthorized AppAttest request", "status", 401)
		return nil, ErrUnauthorized

	case 404:
		c.inner.Logger.Info("no data found for AppAttest receipt", "status", 404)
		return nil, ErrNoDataFound

	case 429:
		c.inner.Logger.Warn("too many AppAttest requests", "status", 429)
		return nil, ErrTooManyRequests

	case 500:
		c.inner.Logger.Error("AppAttest server error", "status", 500)
		return nil, ErrServerError

	case 503:
		c.inner.Logger.Error("AppAttest service unavailable", "status", 503)
		return nil, ErrServiceUnavailable

	default:
		truncated := truncate(string(bodyData), maxErrBodyLen)
		c.inner.Logger.Error("unexpected AppAttest response",
			"status", resp.StatusCode,
			"body", truncated,
		)
		return nil, fmt.Errorf("fraud: unexpected status code %d: %s", resp.StatusCode, truncated)
	}
}

func truncate(s string, n uint) string {
	if uint(len(s)) <= n {
		return s
	}
	idx := int(n)
	for idx > 0 && !utf8.RuneStart(s[idx]) {
		idx--
	}
	return s[:idx] + "..."
}
