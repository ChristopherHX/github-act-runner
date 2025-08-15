package results

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type ResultsService struct {
	Connection *protocol.VssConnection
}

func (rs *ResultsService) UploadBlockFileAsync(ctx context.Context, url, blobStorageType string, fileContent io.Reader) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, fileContent)
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobTypeHeader, AzureBlockBlob)
	}
	response, err := rs.Connection.HTTPClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to upload file, error %v", err.Error())
	}
	defer func() {
		_ = response.Body.Close() // Ignore error for body close
	}()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to upload file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) CreateAppendFileAsync(ctx context.Context, url, blobStorageType string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobTypeHeader, AzureAppendBlob)
		request.Header.Set("Content-Length", "0")
	}
	response, err := rs.Connection.HTTPClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to create append file, error %v", err.Error())
	}
	defer func() {
		_ = response.Body.Close() // Ignore error for body close
	}()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to create append file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) UploadAppendFileAsync(
	ctx context.Context, url, blobStorageType string, fileContent io.Reader, finalize bool, fileSize int64,
) error {
	comp := "&comp=appendblock"
	if finalize {
		comp = "&comp=appendblock&seal=true"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url+comp, fileContent)
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobSealedHeader, fmt.Sprint(finalize))
		request.Header.Set("Content-Length", fmt.Sprint(fileSize))
	}
	response, err := rs.Connection.HTTPClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to upload append file, error %v", err.Error())
	}
	defer func() {
		_ = response.Body.Close() // Ignore error for body close
	}()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to upload append file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) UploadResultsStepSummaryAsync(
	ctx context.Context, planID, jobID, stepID string, fileContent io.Reader, fileSize int64,
) error {
	req := &GetSignedStepSummaryURLRequest{
		WorkflowRunBackendID:    planID,
		WorkflowJobRunBackendID: jobID,
		StepBackendID:           stepID,
	}
	uploadURLResponse := &GetSignedStepSummaryURLResponse{}
	url, err := rs.Connection.BuildURL(GetStepSummarySignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if requestErr := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadURLResponse); requestErr != nil {
		return requestErr
	}
	if uploadURLResponse.SummaryURL == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if fileSize > uploadURLResponse.SoftSizeLimit {
		return fmt.Errorf(
			"file size is larger than the upload url allows, file size: %v, upload url size: %v",
			fileSize,
			uploadURLResponse.SoftSizeLimit,
		)
	}
	err = rs.UploadBlockFileAsync(ctx, uploadURLResponse.SummaryURL, uploadURLResponse.BlobStorageType, fileContent)
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format(TimestampOutputFormat)
	mreq := &StepSummaryMetadataCreate{
		WorkflowJobRunBackendID: jobID,
		WorkflowRunBackendID:    planID,
		StepBackendID:           stepID,
		UploadedAt:              timestamp,
	}
	url, err = rs.Connection.BuildURL(CreateStepSummaryMetadata, nil, nil)
	if err != nil {
		return err
	}
	if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", mreq, nil); err != nil {
		return err
	}
	return nil
}

func (rs *ResultsService) UploadResultsStepLogAsync(
	ctx context.Context, planID, jobID, stepID string, fileContent io.Reader, fileSize int64, finalize, firstBlock bool, lineCount int64,
) error {
	req := &GetSignedStepLogsURLRequest{
		WorkflowRunBackendID:    planID,
		WorkflowJobRunBackendID: jobID,
		StepBackendID:           stepID,
	}
	uploadURLResponse := &GetSignedStepLogsURLResponse{}
	url, err := rs.Connection.BuildURL(GetStepLogsSignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if requestErr := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadURLResponse); requestErr != nil {
		return requestErr
	}
	if uploadURLResponse.LogsURL == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if firstBlock {
		createErr := rs.CreateAppendFileAsync(ctx, uploadURLResponse.LogsURL, uploadURLResponse.BlobStorageType)
		if createErr != nil {
			return createErr
		}
	}
	err = rs.UploadAppendFileAsync(ctx, uploadURLResponse.LogsURL, uploadURLResponse.BlobStorageType, fileContent, finalize, fileSize)
	if err != nil {
		return err
	}
	if finalize {
		timestamp := time.Now().UTC().Format(TimestampOutputFormat)
		req := &StepLogsMetadataCreate{
			WorkflowJobRunBackendID: jobID,
			WorkflowRunBackendID:    planID,
			StepBackendID:           stepID,
			UploadedAt:              timestamp,
			LineCount:               lineCount,
		}
		url, err := rs.Connection.BuildURL(CreateStepLogsMetadata, nil, nil)
		if err != nil {
			return err
		}
		if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, nil); err != nil {
			return err
		}
	}
	return nil
}

func (rs *ResultsService) UploadResultsJobLogAsync(
	ctx context.Context, planID, jobID string, fileContent io.Reader, fileSize int64, finalize, firstBlock bool, lineCount int64,
) error {
	req := &GetSignedJobLogsURLRequest{
		WorkflowRunBackendID:    planID,
		WorkflowJobRunBackendID: jobID,
	}
	uploadURLResponse := &GetSignedJobLogsURLResponse{}
	url, err := rs.Connection.BuildURL(GetJobLogsSignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if requestErr := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadURLResponse); requestErr != nil {
		return requestErr
	}
	if uploadURLResponse.LogsURL == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if firstBlock {
		createErr := rs.CreateAppendFileAsync(ctx, uploadURLResponse.LogsURL, uploadURLResponse.BlobStorageType)
		if createErr != nil {
			return createErr
		}
	}
	err = rs.UploadAppendFileAsync(ctx, uploadURLResponse.LogsURL, uploadURLResponse.BlobStorageType, fileContent, finalize, fileSize)
	if err != nil {
		return err
	}
	if finalize {
		timestamp := time.Now().UTC().Format(TimestampOutputFormat)
		req := &JobLogsMetadataCreate{
			WorkflowJobRunBackendID: jobID,
			WorkflowRunBackendID:    planID,
			UploadedAt:              timestamp,
			LineCount:               lineCount,
		}
		url, err := rs.Connection.BuildURL(CreateJobLogsMetadata, nil, nil)
		if err != nil {
			return err
		}
		if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, nil); err != nil {
			return err
		}
	}
	return nil
}

func (rs *ResultsService) UpdateWorkflowStepsAsync(ctx context.Context, update *StepsUpdateRequest) error {
	url, err := rs.Connection.BuildURL(WorkflowStepsUpdate, nil, nil)
	if err != nil {
		return err
	}
	return rs.Connection.RequestWithContext2(ctx, "POST", url, "", update, nil)
}

var (
	TimestampInputFormat  = "2006-01-02T15:04:05.999Z07:00" // allow to omit fractional seconds
	TimestampOutputFormat = "2006-01-02T15:04:05.000Z07:00" // dotnet "yyyy-MM-dd'T'HH:mm:ss.fffK"

	ResultsReceiverTwirpEndpoint = "twirp/results.services.receiver.Receiver/"
	GetStepSummarySignedBlobURL  = ResultsReceiverTwirpEndpoint + "GetStepSummarySignedBlobURL"
	CreateStepSummaryMetadata    = ResultsReceiverTwirpEndpoint + "CreateStepSummaryMetadata"
	GetStepLogsSignedBlobURL     = ResultsReceiverTwirpEndpoint + "GetStepLogsSignedBlobURL"
	CreateStepLogsMetadata       = ResultsReceiverTwirpEndpoint + "CreateStepLogsMetadata"
	GetJobLogsSignedBlobURL      = ResultsReceiverTwirpEndpoint + "GetJobLogsSignedBlobURL"
	CreateJobLogsMetadata        = ResultsReceiverTwirpEndpoint + "CreateJobLogsMetadata"
	ResultsProtoAPIV1Endpoint    = "twirp/github.actions.results.api.v1.WorkflowStepUpdateService/"
	WorkflowStepsUpdate          = ResultsProtoAPIV1Endpoint + "WorkflowStepsUpdate"

	AzureBlobSealedHeader = "x-ms-blob-sealed"
	AzureBlobTypeHeader   = "x-ms-blob-type"
	AzureBlockBlob        = "BlockBlob"
	AzureAppendBlob       = "AppendBlob"
)
