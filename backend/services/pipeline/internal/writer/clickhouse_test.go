package writer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// countingConn stands in for ClickHouse and counts the rows that reach it.
// What is under test is the buffer the two goroutines share, not the insert,
// so everything else is left to the embedded nil interface: a method this test
// does not expect to be called panics instead of passing quietly.
type countingConn struct {
	driver.Conn
	mu   sync.Mutex
	rows int
}

func (c *countingConn) PrepareBatch(context.Context, string, ...driver.PrepareBatchOption) (driver.Batch, error) {
	return &countingBatch{conn: c}, nil
}

func (c *countingConn) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rows
}

type countingBatch struct {
	driver.Batch
	conn *countingConn
	n    int
}

func (b *countingBatch) Append(...any) error { b.n++; return nil }

func (b *countingBatch) Send() error {
	b.conn.mu.Lock()
	b.conn.rows += b.n
	b.conn.mu.Unlock()
	return nil
}

func anEvent() *event.NormalizedEvent {
	return &event.NormalizedEvent{
		EventID:       uuid.New(),
		TenantID:      uuid.New().String(),
		Timestamp:     time.Now().UTC(),
		IngestedAt:    time.Now().UTC(),
		Source:        "test",
		SourceType:    "test",
		ConnectorID:   uuid.New().String(),
		Action:        "login",
		Category:      event.CategoryIAM,
		Severity:      event.SeverityLow,
		Outcome:       event.OutcomeSuccess,
		SchemaVersion: 1,
	}
}

// The consumer loop writes while the flush loop flushes. Every event handed to
// the writer has already been committed as consumed by the time it is flushed,
// so one lost to a race is lost for good — hence the count, not just the
// absence of a panic. Run with -race, which is what CI does.
func TestWritingAndFlushingAtTheSameTimeLosesNothing(t *testing.T) {
	conn := &countingConn{}
	w := NewClickHouseWriter(conn, zerolog.Nop(), 50)

	const events = 2000
	ctx := context.Background()
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < events; i++ {
			if err := w.Write(ctx, anEvent()); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
		}
	}()

	flushing := make(chan struct{})
	go func() {
		defer close(flushing)
		for {
			select {
			case <-done:
				return
			default:
				if err := w.Flush(ctx); err != nil {
					t.Errorf("flush: %v", err)
					return
				}
			}
		}
	}()

	<-done
	<-flushing
	if err := w.Flush(ctx); err != nil {
		t.Fatalf("final flush: %v", err)
	}

	if got := conn.total(); got != events {
		t.Fatalf("ClickHouse received %d rows, %d were written", got, events)
	}
}
