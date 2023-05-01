package results

import (
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type GetSignedStepSummaryURLRequest struct {
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
	StepBackendId           string `json:"step_backend_id,omitempty"`
}

type GetSignedStepSummaryURLResponse struct {
	SummaryUrl      string `json:"summary_url,omitempty"`
	SoftSizeLimit   int64  `json:"soft_size_limit,omitempty"`
	BlobStorageType string `json:"blob_storage_type,omitempty"`
}

type StepSummaryMetadataCreate struct {
	StepBackendId           string `json:"step_backend_id,omitempty"`
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	Size                    int64  `json:"size,omitempty"`
	UploadedAt              string `json:"uploaded_at,omitempty"`
}

type GetSignedJobLogsURLRequest struct {
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
}

type GetSignedJobLogsURLResponse struct {
	LogsUrl         string `json:"logs_url,omitempty"`
	BlobStorageType string `json:"blob_storage_type,omitempty"`
}

type GetSignedStepLogsURLRequest struct {
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
	StepBackendId           string `json:"step_backend_id,omitempty"`
}

type GetSignedStepLogsURLResponse struct {
	LogsUrl         string `json:"logs_url,omitempty"`
	BlobStorageType string `json:"blob_storage_type,omitempty"`
	SoftSizeLimit   int64  `json:"soft_size_limit,omitempty"`
}

type JobLogsMetadataCreate struct {
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	UploadedAt              string `json:"uploaded_at,omitempty"`
	LineCount               int64  `json:"line_count,omitempty"`
}

type StepLogsMetadataCreate struct {
	WorkflowRunBackendId    string `json:"workflow_run_backend_id,omitempty"`
	WorkflowJobRunBackendId string `json:"workflow_job_run_backend_id,omitempty"`
	StepBackendId           string `json:"step_backend_id,omitempty"`
	UploadedAt              string `json:"uploaded_at,omitempty"`
	LineCount               int64  `json:"line_count,omitempty"`
}

type CreateMetadataResponse struct {
	Ok bool `json:"ok,omitempty"`
}

type StepsUpdateRequest struct {
	Steps                   []Step `json:"steps"`
	ChangeOrder             int64  `json:"change_order"`
	WorkflowJobRunBackendID string `json:"workflow_job_run_backend_id"`
	WorkflowRunBackendID    string `json:"workflow_run_backend_id"`
}

type Step struct {
	ExternalID  string     `json:"external_id"`
	Number      int32      `json:"number"`
	Name        string     `json:"name"`
	Status      Status     `json:"status"`
	StartedAt   string     `json:"started_at,omitempty"`
	CompletedAt string     `json:"completed_at,omitempty"`
	Conclusion  Conclusion `json:"conclusion"`
}

type Status int

const (
	StatusUnknown Status = iota
	StatusInProgress
	StatusPending
	StatusCompleted
)

type Conclusion int

const (
	ConclusionUnknown   Conclusion = 0
	ConclusionSuccess   Conclusion = 2
	ConclusionFailure   Conclusion = 3
	ConclusionCancelled Conclusion = 4
	ConclusionSkipped   Conclusion = 7
)

func ConvertTimelineRecordToStep(r protocol.TimelineRecord) Step {
	return Step{
		ExternalID:  r.ID,
		Number:      r.Order,
		Name:        r.Name,
		Status:      ConvertStateToStatus(r.State),
		StartedAt:   ConvertTimestamp(&r.StartTime),
		CompletedAt: ConvertTimestamp(r.FinishTime),
		Conclusion:  ConvertResultToConclusion(r.Result),
	}
}

func ConvertTimestamp(s *string) string {
	if s == nil || *s == "" {
		return ""
	}
	if t, err := time.Parse(protocol.TimestampInputFormat, *s); err != nil {
		return t.Format(TimestampOutputFormat)
	}
	return ""
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

func ConvertResultToConclusion(s *string) Conclusion {
	if s == nil {
		return ConclusionUnknown
	}
	switch *s {
	case "Succeeded":
		return ConclusionSuccess
	case "Skipped":
		return ConclusionSkipped
	case "Failed":
		return ConclusionFailure
	case "Canceled":
		return ConclusionCancelled
	default:
		return ConclusionUnknown
	}
}

var (
	BlobStorageTypeAzureBlobStorage = "BLOB_STORAGE_TYPE_AZURE"
	BlobStorageTypeUnspecified      = "BLOB_STORAGE_TYPE_UNSPECIFIED"
)
