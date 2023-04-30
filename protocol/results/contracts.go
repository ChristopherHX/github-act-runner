package results

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

var (
	BlobStorageTypeAzureBlobStorage = "BLOB_STORAGE_TYPE_AZURE"
	BlobStorageTypeUnspecified      = "BLOB_STORAGE_TYPE_UNSPECIFIED"
)
