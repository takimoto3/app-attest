// Package appattest provides a client for Apple's App Attest
// attestation data verification API.
//
// It allows requesting the attestation receipt and interpreting
// Apple’s response according to the App Attest specification.
package fraud

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
)

var (
	// ErrNotModified indicates that the request was made before the previous
	// receipt’s “Not Before” date (HTTP 304).
	ErrNotModified = errors.New("you made the request before the previous receipt’s 'Not Before' date")

	// ErrIncorrectEnvironment indicates that a development receipt was used
	// in production, or vice versa (HTTP 400).
	ErrIncorrectEnvironment = errors.New("you used a development receipt in production, or vice versa")

	// ErrBadPayload indicates that the request has a missing or badly formatted payload (HTTP 400).
	ErrBadPayload = errors.New("your request has a missing or badly formatted payload")

	// ErrUnauthorized indicates that the authentication token is invalid or does not match the receipt (HTTP 401).
	ErrUnauthorized = errors.New("you used an authentication token that the apple server can’t verify or that doesn’t match the receipt")

	// ErrNoDataFound indicates that there is no data available for the supplied receipt (HTTP 404).
	ErrNoDataFound = errors.New("no data available for the supplied receipt")

	// ErrTooManyRequests indicates that the client sent too many requests (HTTP 429).
	ErrTooManyRequests = errors.New("you sent too many requests to the server")

	// ErrServerError indicates a server-side error occurred (HTTP 500).
	ErrServerError = errors.New("an error occurred on the server")

	// ErrServiceUnavailable indicates that the service is temporarily unavailable (HTTP 503).
	ErrServiceUnavailable = errors.New("service is temporarily unavailable due to overload or maintenance")
)

// Client provides access to the App Attest attestation data endpoint.
// It wraps appleapi.Client and automatically selects the production or
// development host depending on the client configuration.
type Client struct {
	inner *appleapi.Client
}

// Response represents a successful attestation data response from Apple.
// The Receipt field contains the decoded binary receipt.
type Response struct {
	Receipt []byte
}

// NewClient returns a new Client instance for the App Attest API.
// The host is automatically set to the development or production endpoint
// based on the configuration of the underlying appleapi.Client.
func NewClient(tp token.Provider, opts ...appleapi.Option) (*Client, error) {
	return NewClientFromInitializer(appleapi.DefaultHTTPClientInitializer(), tp, opts...)
}

func NewClientFromInitializer(initializer appleapi.HTTPClientInitializer, tp token.Provider, opts ...appleapi.Option) (*Client, error) {
	c, err := appleapi.NewClient(initializer, ProductionHost, tp, opts...)
	if err != nil {
		return nil, err
	}

	if c.Development {
		c.Host = DevelopmentHost
	}

	return &Client{inner: c}, nil
}

// Do sends a base64-encoded attestation receipt to Apple’s attestation
// data endpoint and returns the decoded receipt on success.
//
// Possible error values correspond to Apple’s documented HTTP status codes:
//
//   - ErrNotModified (304)
//   - ErrIncorrectEnvironment, ErrBadPayload (400)
//   - ErrUnauthorized (401)
//   - ErrNoDataFound (404)
//   - ErrTooManyRequests (429)
//   - ErrServerError (500)
//   - ErrServiceUnavailable (503)
func (c *Client) Do(ctx context.Context, receipt []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.inner.Host+Path, bytes.NewBuffer(receipt))
	if err != nil {
		c.inner.Logger.Error("failed to create AppAttest request", "error", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		c.inner.Logger.Error("failed to perform AppAttest request", "error", err)
		return nil, fmt.Errorf("failed to perform attestation request: %w", err)
	}
	defer resp.Body.Close()

	return c.handleResponse(resp)
}

// handleResponse interprets the HTTP response from Apple's App Attest service
// and maps status codes to predefined error values.
func (c *Client) handleResponse(resp *http.Response) (*Response, error) {
	bodyData, err := io.ReadAll(resp.Body)
	if err != nil {
		c.inner.Logger.Error("failed to read AppAttest response body",
			"status", resp.StatusCode,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	body := strings.TrimSpace(string(bodyData))

	c.inner.Logger.Debug("AppAttest response received",
		"status", resp.StatusCode,
		"body", body,
	)

	switch resp.StatusCode {
	case 200:
		receipt, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			c.inner.Logger.Warn("invalid base64 in AppAttest response", "error", err)
			return nil, fmt.Errorf("failed to decode base64 receipt from response body: %w", err)
		}
		return &Response{receipt}, nil

	case 304:
		c.inner.Logger.Info("AppAttest not modified", "status", 304)
		return nil, ErrNotModified

	case 400:
		switch {
		case strings.Contains(body, "Incorrect Environment"):
			c.inner.Logger.Warn("incorrect environment", "status", 400)
			return nil, ErrIncorrectEnvironment
		case strings.Contains(body, "Bad Payload"):
			c.inner.Logger.Warn("bad payload", "status", 400)
			return nil, ErrBadPayload
		default:
			c.inner.Logger.Warn("bad request", "status", 400, "body", body)
			return nil, fmt.Errorf("bad request: %s", body)
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
		c.inner.Logger.Error("unexpected AppAttest response",
			"status", resp.StatusCode,
			"body", body,
		)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, body)
	}
}
