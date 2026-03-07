package logger

import (
	"sync"
	"testing"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

// mockLiveLogger is a no-op LiveLogger used for testing.
type mockLiveLogger struct{}

func (*mockLiveLogger) Close() error                                             { return nil }
func (*mockLiveLogger) SendLog(_ *protocol.TimelineRecordFeedLinesWrapper) error { return nil }

const (
	// Test timeline entry reference names
	initRefName  = "_init"
	init3RefName = "_init3"
)

func TestJobLogger(t *testing.T) {
	logger := &JobLogger{
		TimelineRecords: &protocol.TimelineRecordWrapper{},
	}
	entry1 := protocol.CreateTimelineEntry("", initRefName, "Init")
	logger.Append(&entry1).Start()
	entry2 := protocol.CreateTimelineEntry("", init3RefName, "Init")
	logger.Append(&entry2).Start()
	if logger.TimelineRecords.Value[0].RefName != initRefName {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[1].RefName != init3RefName {
		t.FailNow()
	}
	entry3 := protocol.CreateTimelineEntry("", "_init0", "Init")
	logger.Insert(&entry3).Start()
	if logger.TimelineRecords.Value[1].RefName != initRefName {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[2].RefName != init3RefName {
		t.FailNow()
	}
}

// TestBufferedLiveLoggerConcurrentCloseAndSend verifies that concurrent calls
// to Close and SendLog do not panic (send on closed channel) or data-race.
// Run with: go test -race ./protocol/logger/...
func TestBufferedLiveLoggerConcurrentCloseAndSend(t *testing.T) {
	const goroutines = 20
	const iters = 50
	for i := 0; i < iters; i++ {
		bl := &BufferedLiveLogger{
			LiveLogger: &mockLiveLogger{},
		}
		var wg sync.WaitGroup
		// Spawn goroutines that each send one log entry (fresh wrapper per call).
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = bl.SendLog(&protocol.TimelineRecordFeedLinesWrapper{
					Value: []string{"hello"},
					Count: 1,
				})
			}()
		}
		// Close concurrently with the sends.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = bl.Close()
		}()
		wg.Wait()
	}
}
