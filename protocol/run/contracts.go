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
