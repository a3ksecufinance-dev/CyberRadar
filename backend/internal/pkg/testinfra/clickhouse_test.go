package testinfra

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Readiness, when the port is bound before the server is listening.
//
// This is the failure that turned the CI job red: the ClickHouse container was
// declared ready and refused the connection in the same millisecond, and the
// single ping behind it had no second chance. A test that only checked "ping
// succeeds against a working server" would have passed throughout.

type scriptedPinger struct {
	// failures is how many attempts fail before one succeeds. A negative
	// value never succeeds.
	failures int
	calls    int
}

func (p *scriptedPinger) Ping(context.Context) error {
	p.calls++
	if p.failures < 0 || p.calls <= p.failures {
		return errors.New("read: connection reset by peer")
	}
	return nil
}

func TestPingRetriesUntilTheServerAnswers(t *testing.T) {
	p := &scriptedPinger{failures: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pingUntilReady(ctx, p, time.Millisecond); err != nil {
		t.Fatalf("pingUntilReady = %v, want nil — three resets then an answer "+
			"is exactly what a starting container does", err)
	}
	if p.calls != 4 {
		t.Errorf("pinged %d times, want 4 — one attempt per failure plus the "+
			"one that succeeded", p.calls)
	}
}

// The regression itself: one reset must not be fatal.
func TestASingleResetIsNotFatal(t *testing.T) {
	p := &scriptedPinger{failures: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pingUntilReady(ctx, p, time.Millisecond); err != nil {
		t.Fatalf("pingUntilReady = %v, want nil", err)
	}
	if p.calls != 2 {
		t.Errorf("pinged %d times, want 2", p.calls)
	}
}

func TestAServerThatAnswersAtOnceIsNotDelayed(t *testing.T) {
	p := &scriptedPinger{failures: 0}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	started := time.Now()
	if err := pingUntilReady(ctx, p, time.Hour); err != nil {
		t.Fatalf("pingUntilReady = %v, want nil", err)
	}
	if p.calls != 1 {
		t.Errorf("pinged %d times, want 1", p.calls)
	}
	// With an hour between attempts, anything slow means it slept first.
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("took %s — a server that answers must not wait for the interval", elapsed)
	}
}

// A server that never comes up must still fail, and say what it saw. Retrying
// forever would turn a broken dependency into a hung suite.
func TestAServerThatNeverAnswersStillFails(t *testing.T) {
	p := &scriptedPinger{failures: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err := pingUntilReady(ctx, p, 10*time.Millisecond)
	if err == nil {
		t.Fatal("pingUntilReady = nil, want an error — the server never answered")
	}
	if !strings.Contains(err.Error(), "connection reset by peer") {
		t.Errorf("error = %q, want the last ping failure in it — without it "+
			"the reader cannot tell a refused port from a wrong password", err)
	}
	if !strings.Contains(err.Error(), "attempts") {
		t.Errorf("error = %q, want the attempt count in it", err)
	}
	if p.calls < 2 {
		t.Errorf("pinged %d times, want several within the deadline", p.calls)
	}
}

// The deadline has to be honoured, or a dead dependency hangs CI instead of
// failing it.
func TestTheDeadlineIsHonoured(t *testing.T) {
	p := &scriptedPinger{failures: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	if err := pingUntilReady(ctx, p, 10*time.Millisecond); err == nil {
		t.Fatal("pingUntilReady = nil, want an error")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("returned after %s, want shortly after the 100ms deadline", elapsed)
	}
}
