package logger

import (
	"testing"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

func TestJobLogger(t *testing.T) {
	logger := &JobLogger{
		TimelineRecords: &protocol.TimelineRecordWrapper{},
	}
	logger.Append(protocol.CreateTimelineEntry("", "_init", "Init")).Start()
	logger.Append(protocol.CreateTimelineEntry("", "_init3", "Init")).Start()
	if logger.TimelineRecords.Value[0].RefName != "_init" {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[1].RefName != "_init3" {
		t.FailNow()
	}
	logger.Insert(protocol.CreateTimelineEntry("", "_init0", "Init")).Start()
	if logger.TimelineRecords.Value[1].RefName != "_init" {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[2].RefName != "_init3" {
		t.FailNow()
	}
}
