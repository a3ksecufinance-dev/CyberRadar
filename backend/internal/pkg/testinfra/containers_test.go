package testinfra

import (
	"context"
	"strings"
	"testing"
	"time"
)

// awaitBroker gives up on a cancelled context rather than spinning until its
// own deadline.
//
// The wait exists because a KRaft broker opens 9092 before it will answer.
// The risk of any such loop is the opposite failure: a broker that never
// comes up holding the suite for the full three minutes, or for ever. This
// pins the context path, which is the one a cancelled test run takes.
func TestAwaitBrokerStopsWhenTheContextDoes(t *testing.T) {
	// Port 1 on the loopback: nothing listens, and nothing is expected to.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := awaitBroker(ctx, "127.0.0.1:1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a broker that is not there was reported as ready")
	}
	if elapsed > 10*time.Second {
		t.Errorf("waited %s for a cancelled context; startupTimeout is %s and must not be reached here",
			elapsed, startupTimeout)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("the error does not say which broker it gave up on: %v", err)
	}
}
