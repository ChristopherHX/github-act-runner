package logger

import (
	"testing"

	"github.com/ChristopherHX/github-act-runner/protocol"
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
