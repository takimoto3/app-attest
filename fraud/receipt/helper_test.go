package receipt_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// wantError describes an expected error as a message fragment plus the
// sentinel errors that the returned error must wrap.
type wantError struct {
	msg       string  // must be contained in got.Error()
	sentinels []error // each must satisfy errors.Is(got, sentinel)
}

// expectError builds an expectation from at most one string (message
// fragment) and any number of errors (sentinels checked with errors.Is).
// It panics on misuse, since that is a bug in the test table.
func expectError(args ...any) *wantError {
	w := &wantError{}
	for i, a := range args {
		switch v := a.(type) {
		case string:
			if w.msg != "" {
				panic("expectError: more than one message fragment")
			}
			w.msg = v
		case error:
			w.sentinels = append(w.sentinels, v)
		default:
			// also catches a nil sentinel (untyped nil -> %T is <nil>)
			panic(fmt.Sprintf("expectError: arg %d: unsupported type %T", i, a))
		}
	}
	if w.msg == "" && len(w.sentinels) == 0 {
		panic("expectError: no message and no sentinels would accept any error")
	}
	return w
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
			t.Errorf("error %q does not wrap %v", got, s)
		}
	}
	return false
}
