package protocol

import (
	"testing"
)

func TestJobLogger(t *testing.T) {
	logger := &JobLogger{
		TimelineRecords: &TimelineRecordWrapper{},
		CurrentLine:     1,
		CurrentRecord:   0,
	}
	logger.Append(CreateTimelineEntry("", "_init", "Init")).Start()
	logger.Append(CreateTimelineEntry("", "_init3", "Init")).Start()
	if logger.TimelineRecords.Value[0].RefName != "_init" {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[1].RefName != "_init3" {
		t.FailNow()
	}
	logger.Insert(CreateTimelineEntry("", "_init0", "Init")).Start()
	if logger.TimelineRecords.Value[1].RefName != "_init" {
		t.FailNow()
	}
	if logger.TimelineRecords.Value[2].RefName != "_init3" {
		t.FailNow()
	}
}
