package attest_test

import (
	"errors"
	"strings"
	"testing"
)

// wantError describes an expected error as a message fragment plus the
// sentinel errors that the returned error must wrap.
type wantError struct {
	msg       string  // must be contained in got.Error()
	sentinels []error // each must satisfy errors.Is(got, sentinel)
}

func (w *wantError) Error() string { return w.msg }

// wrap checks the message fragment and, optionally, the %w chain.
func wrap(msg string, sentinels ...error) *wantError {
	return &wantError{msg: msg, sentinels: sentinels}
}

// is checks only errors.Is, ignoring the message.
func is(sentinels ...error) *wantError {
	return &wantError{sentinels: sentinels}
}

// assertErr verifies got against want and reports whether the test
// should continue (true only when no error was expected and none occurred).
func assertErr(t *testing.T, got error, want *wantError) (proceed bool) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("unexpected error: %v", got)
		}
		return true
	}
	if got == nil {
		t.Fatalf("expected error, got nil (want %q, %v)", want.msg, want.sentinels)
	}
	if want.msg != "" && !strings.Contains(got.Error(), want.msg) {
		t.Errorf("error = %q, want containing %q", got, want.msg)
	}
	for _, s := range want.sentinels {
		if !errors.Is(got, s) {
			t.Errorf("error %q is not errors.Is(%v)", got, s)
		}
	}
	return false
}
