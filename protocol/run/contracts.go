package run

import (
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type AcquireJobRequest struct {
	StreamID     string `json:"streamId,omitempty"` // Deprecated: https://github.com/actions/runner/pull/2547
	JobMessageID string `json:"jobMessageId"`
}
type CompleteJobRequest struct {
	PlanID      string                            `json:"planId,omitempty"`
	JobID       string                            `json:"jobId,omitempty"`
	Conclusion  string                            `json:"conclusion"`
	Outputs     map[string]protocol.VariableValue `json:"outputs,omitempty"`
	StepResults []StepResult                      `json:"stepResults,omitempty"`
}

type RenewJobRequest struct {
	PlanID string `json:"planId,omitempty"`
	JobID  string `json:"jobId,omitempty"`
}

type RenewJobResponse struct {
	LockedUntil time.Time `json:"lockedUntil"`
}
type StepResult struct {
	ExternalID        string  `json:"external_id,omitempty"`
	Number            *int    `json:"number,omitempty"`
	Name              string  `json:"name,omitempty"`
	Status            *string `json:"status,omitempty"`
	Conclusion        *string `json:"conclusion,omitempty"`
	StartedAt         *string `json:"started_at,omitempty"`
	CompletedAt       *string `json:"completed_at,omitempty"`
	CompletedLogURL   string  `json:"completed_log_url,omitempty"`
	CompletedLogLines *int64  `json:"completed_log_lines,omitempty"`
}
type StepsUpdateRequest struct {
	Steps                   []Step `json:"steps"`
	ChangeOrder             int64  `json:"change_order"`
	WorkflowJobRunBackendID string `json:"workflow_job_run_backend_id"`
	WorkflowRunBackendID    string `json:"workflow_run_backend_id"`
}

type Step struct {
	ExternalID  string `json:"external_id"`
	Number      int32  `json:"number"`
	Name        string `json:"name"`
	Status      Status `json:"status"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type Status int

const (
	StatusUnknown Status = iota
	StatusInProgress
	StatusPending
	StatusCompleted
)

func ConvertTimelineRecordToStep(r protocol.TimelineRecord) Step {
	return Step{
		ExternalID:  r.ID,
		Number:      r.Order,
		Name:        r.Name,
		Status:      ConvertStateToStatus(r.State),
		StartedAt:   r.StartTime,
		CompletedAt: *r.FinishTime,
	}
}

func ConvertStateToStatus(s string) Status {
	switch s {
	case "Completed":
		return StatusCompleted
	case "Pending":
		return StatusPending
	case "InProgress":
		return StatusInProgress
	default:
		return StatusUnknown
	}
}
