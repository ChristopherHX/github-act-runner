package logger

import (
	"fmt"
	"testing"

	"github.com/ChristopherHX/github-act-runner/protocol"

	"github.com/stretchr/testify/require"
)

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

type TestLiveLogger struct {
	*testing.T
}

// Close implements [LiveLogger].
func (t *TestLiveLogger) Close() error {
	return nil
}

// SendLog implements [LiveLogger].
func (t *TestLiveLogger) SendLog(lines *protocol.TimelineRecordFeedLinesWrapper) error {
	return nil
}

func getTestLiveLogger(t *testing.T) LiveLogger {
	return &TestLiveLogger{
		T: t,
	}
}

func TestBufferedLiveLoggerDrain(t *testing.T) {
	t.Parallel()
	bufferedLogger := &BufferedLiveLogger{
		LiveLogger: getTestLiveLogger(t),
	}

	logchan := make(chan *protocol.TimelineRecordFeedLinesWrapper)
	logdrain := make(chan struct{})
	logfinished := make(chan struct{})

	t.Run("forwardLogs", func(t *testing.T) {
		t.Parallel()
		bufferedLogger.sendLogs(logchan, logdrain, logfinished)
	})

	t.Run("sendLogs", func(t *testing.T) {
		t.Parallel()
		logchan <- &protocol.TimelineRecordFeedLinesWrapper{
			Count: 1,
			Value: []string{"line1"},
		}
		logchan <- &protocol.TimelineRecordFeedLinesWrapper{
			Count: 1,
			Value: []string{"line2"},
		}
		close(logdrain)
		<-logfinished
	})
}

func TestBufferedLiveLogger(t *testing.T) {
	t.Parallel()
	bufferedLogger := &BufferedLiveLogger{
		LiveLogger: getTestLiveLogger(t),
	}

	require.NoError(t, bufferedLogger.SendLog(&protocol.TimelineRecordFeedLinesWrapper{
		Count: 1,
		Value: []string{"line1"},
	}))

	t.Run("close", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, bufferedLogger.Close())
	})

	t.Run("sendLogs", func(t *testing.T) {
		t.Parallel()
		var err error
		for i := range 100 {
			err = bufferedLogger.SendLog(&protocol.TimelineRecordFeedLinesWrapper{
				Count: 1,
				Value: []string{fmt.Sprintf("line %v", (i + 1))},
			})
			if err != nil {
				break
			}
		}
		require.Error(t, err)
	})
}
