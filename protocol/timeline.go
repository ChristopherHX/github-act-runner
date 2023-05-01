package protocol

import (
	"time"

	"github.com/google/uuid"
)

type TimeLineReference struct {
	ID       string
	ChangeID int
	Location *interface{}
}

type Issue struct {
	Type                  string // notice, error or warning
	Category              string
	Message               string
	IsInfrastructureIssue *bool
	Data                  map[string]string
}

type TimelineAttempt struct {
}

type TimelineRecord struct {
	ID               string
	TimelineID       string
	ParentID         string
	Type             string
	Name             string
	StartTime        string
	FinishTime       *string
	CurrentOperation *string
	PercentComplete  int32
	State            string
	Result           *string
	ResultCode       *string
	ChangeID         int32
	LastModified     string
	WorkerName       string
	Order            int32
	RefName          string
	Log              *TaskLogReference
	Details          *TimeLineReference
	ErrorCount       int
	WarningCount     int
	Issues           []Issue
	Location         string
	Attempt          int32
	Identifier       *string
	AgentPlatform    string
	PreviousAttempts []TimelineAttempt
	Variables        map[string]VariableValue
}

type TimelineRecordWrapper struct {
	Count int64
	Value []*TimelineRecord
}

type TimelineRecordFeedLinesWrapper struct {
	Count     int64
	Value     []string
	StepID    string
	StartLine *int64
}

func (rec *TimelineRecord) Start() {
	time := time.Now().UTC().Format(TimestampOutputFormat)
	rec.PercentComplete = 0
	rec.State = "InProgress"
	rec.StartTime = time
	rec.FinishTime = nil
	rec.LastModified = time
}

func (rec *TimelineRecord) Complete(res string) {
	time := time.Now().UTC().Format(TimestampOutputFormat)
	rec.PercentComplete = 100
	rec.State = "Completed"
	rec.FinishTime = &time
	rec.LastModified = time
	rec.Result = &res
}

func CreateTimelineEntry(parent string, refname string, name string) TimelineRecord {
	record := TimelineRecord{}
	record.ID = uuid.New().String()
	record.RefName = refname
	record.Name = name
	record.Type = "Task"
	record.WorkerName = "golang-go"
	record.ParentID = parent
	record.State = "Pending"
	record.LastModified = time.Now().UTC().Format(TimestampOutputFormat)
	record.Order = 1
	return record
}
