package run

import (
	"strconv"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type AcquireJobRequest struct {
	StreamID     string `json:"streamId,omitempty"` // Deprecated: https://github.com/actions/runner/pull/2547
	JobMessageID string `json:"jobMessageId"`
}

type Telemetry struct {
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
}

type CompleteJobRequest struct {
	PlanID         string                            `json:"planId,omitempty"`
	JobID          string                            `json:"jobId,omitempty"`
	Conclusion     string                            `json:"conclusion"`
	Outputs        map[string]protocol.VariableValue `json:"outputs,omitempty"`
	StepResults    []StepResult                      `json:"stepResults,omitempty"`
	Annotations    []Annotation                      `json:"annotations,omitempty"`
	Telemetry      []Telemetry                       `json:"telemetry,omitempty"`
	EnvironmentURL string                            `json:"environmentUrl,omitempty"`
}

type RenewJobRequest struct {
	PlanID string `json:"planId,omitempty"`
	JobID  string `json:"jobId,omitempty"`
}

type RenewJobResponse struct {
	LockedUntil time.Time `json:"lockedUntil"`
}
type StepResult struct {
	ExternalID        string       `json:"external_id,omitempty"`
	Number            int          `json:"number,omitempty"`
	Name              string       `json:"name,omitempty"`
	ActionName        string       `json:"action_name,omitempty"`
	Status            string       `json:"status,omitempty"`
	Conclusion        *string      `json:"conclusion,omitempty"`
	StartedAt         string       `json:"started_at,omitempty"`
	CompletedAt       *string      `json:"completed_at,omitempty"`
	CompletedLogURL   string       `json:"completed_log_url,omitempty"`
	CompletedLogLines *int64       `json:"completed_log_lines,omitempty"`
	Annotations       []Annotation `json:"annotations,omitempty"`
}

func toLowerStringP(p *string) *string {
	if p == nil {
		return nil
	}
	ret := strings.ToLower(*p)
	return &ret
}

func TimeLineRecordToStepResult(rec protocol.TimelineRecord) StepResult {
	annotations := make([]Annotation, len(rec.Issues))
	for i, issue := range rec.Issues {
		annotations[i] = IssueToAnnotation(issue)
	}

	return StepResult{
		ExternalID:  rec.ID,
		Conclusion:  toLowerStringP(rec.Result),
		Status:      strings.ToLower(rec.State),
		Number:      int(rec.Order),
		Name:        rec.Name,
		StartedAt:   rec.StartTime,
		CompletedAt: rec.FinishTime,
	}
}

func IssueToAnnotation(issue protocol.Issue) Annotation {
	path := issue.Data["file"]
	lineNumber := IssueGetAnnotationNumber(issue, "line", 0)
	endLineNumber := IssueGetAnnotationNumber(issue, "endLine", lineNumber)
	columnNumber := IssueGetAnnotationNumber(issue, "col", 0)
	endColumnNumber := IssueGetAnnotationNumber(issue, "endColumn", columnNumber)
	logLineNumber := IssueGetAnnotationNumber(issue, "logLineNumber", 0)
	stepNumber := IssueGetAnnotationNumber(issue, "stepNumber", 0)
	if path == "" && lineNumber == 0 && logLineNumber != 0 {
		lineNumber = logLineNumber
		endLineNumber = logLineNumber
	}
	return Annotation{
		Level:       IssueGetAnnotationLevel(issue.Type),
		Message:     issue.Message,
		Path:        path,
		StartLine:   lineNumber,
		EndLine:     endLineNumber,
		StartColumn: columnNumber,
		EndColumn:   endColumnNumber,
		StepNumber:  stepNumber,
	}
}

func IssueGetAnnotationLevel(issueType string) AnnotationLevel {
	switch strings.ToLower(issueType) {
	case "error":
		return FAILURE
	case "warning":
		return WARNING
	case "notice":
		return NOTICE
	default:
		return UNKNOWN
	}
}

func IssueGetAnnotationNumber(issue protocol.Issue, name string, def int64) int64 {
	if v, ok := issue.Data[name]; ok {
		if r, err := strconv.ParseInt(v, 10, 64); err == nil {
			return r
		}
	}
	return def
}
