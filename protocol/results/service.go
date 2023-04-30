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

func (rs *ResultsService) UploadBlockFileAsync(ctx context.Context, url string, blobStorageType string, fileContent io.Reader) error {
	request, err := http.NewRequestWithContext(ctx, "PUT", url, fileContent)
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobTypeHeader, AzureBlockBlob)
	}
	response, err := rs.Connection.HttpClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to upload file, error %v", err.Error())
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to upload file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) CreateAppendFileAsync(ctx context.Context, url string, blobStorageType string) error {
	request, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobTypeHeader, AzureAppendBlob)
		request.Header.Set("Content-Length", "0")
	}
	response, err := rs.Connection.HttpClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to create append file, error %v", err.Error())
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to create append file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) UploadAppendFileAsync(ctx context.Context, url string, blobStorageType string, fileContent io.Reader, finalize bool, fileSize int64) error {
	comp := "&comp=appendblock"
	if finalize {
		comp = "&comp=appendblock&seal=true"
	}
	request, err := http.NewRequestWithContext(ctx, "PUT", url+comp, fileContent)
	if err != nil {
		return err
	}
	if blobStorageType == BlobStorageTypeAzureBlobStorage {
		request.Header.Set(AzureBlobSealedHeader, fmt.Sprint(finalize))
		request.Header.Set("Content-Length", fmt.Sprint(fileSize))
	}
	response, err := rs.Connection.HttpClient().Do(request)
	if err != nil {
		return fmt.Errorf("failed to upload append file, error %v", err.Error())
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("failed to upload append file, status code: %v", response.StatusCode)
}

func (rs *ResultsService) UploadResultsStepSummaryAsync(ctx context.Context, planId string, jobId string, stepId string, fileContent io.Reader, fileSize int64) error {
	req := &GetSignedStepSummaryURLRequest{
		WorkflowRunBackendId:    planId,
		WorkflowJobRunBackendId: jobId,
		StepBackendId:           jobId,
	}
	uploadUrlResponse := &GetSignedStepSummaryURLResponse{}
	url, err := rs.Connection.BuildURL(GetStepSummarySignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadUrlResponse); err != nil {
		return err
	}
	if uploadUrlResponse.SummaryUrl == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if fileSize > uploadUrlResponse.SoftSizeLimit {
		return fmt.Errorf("file size is larger than the upload url allows, file size: %v, upload url size: %v", fileSize, uploadUrlResponse.SoftSizeLimit)
	}
	err = rs.UploadBlockFileAsync(ctx, uploadUrlResponse.SummaryUrl, uploadUrlResponse.BlobStorageType, fileContent)
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format(TimestampOutputFormat)
	mreq := &StepSummaryMetadataCreate{
		WorkflowJobRunBackendId: jobId,
		WorkflowRunBackendId:    planId,
		StepBackendId:           stepId,
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

func (rs *ResultsService) UploadResultsStepLogAsync(ctx context.Context, planId string, jobId string, stepId string, fileContent io.Reader, fileSize int64, finalize bool, firstBlock bool, lineCount int64) error {
	req := &GetSignedStepLogsURLRequest{
		WorkflowRunBackendId:    planId,
		WorkflowJobRunBackendId: jobId,
		StepBackendId:           jobId,
	}
	uploadUrlResponse := &GetSignedStepLogsURLResponse{}
	url, err := rs.Connection.BuildURL(GetStepLogsSignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadUrlResponse); err != nil {
		return err
	}
	if uploadUrlResponse.LogsUrl == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if !firstBlock {
		err := rs.CreateAppendFileAsync(ctx, uploadUrlResponse.LogsUrl, uploadUrlResponse.BlobStorageType)
		if err != nil {
			return err
		}
	}
	err = rs.UploadAppendFileAsync(ctx, uploadUrlResponse.LogsUrl, uploadUrlResponse.BlobStorageType, fileContent, finalize, fileSize)
	if err != nil {
		return err
	}
	if finalize {
		timestamp := time.Now().UTC().Format(TimestampOutputFormat)
		req := &StepLogsMetadataCreate{
			WorkflowJobRunBackendId: jobId,
			WorkflowRunBackendId:    planId,
			StepBackendId:           stepId,
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

func (rs *ResultsService) UploadResultsJobLogAsync(ctx context.Context, planId string, jobId string, fileContent io.Reader, fileSize int64, finalize bool, firstBlock bool, lineCount int64) error {
	req := &GetSignedJobLogsURLRequest{
		WorkflowRunBackendId:    planId,
		WorkflowJobRunBackendId: jobId,
	}
	uploadUrlResponse := &GetSignedJobLogsURLResponse{}
	url, err := rs.Connection.BuildURL(GetJobLogsSignedBlobURL, nil, nil)
	if err != nil {
		return err
	}
	if err := rs.Connection.RequestWithContext2(ctx, "POST", url, "", req, uploadUrlResponse); err != nil {
		return err
	}
	if uploadUrlResponse.LogsUrl == "" {
		return fmt.Errorf("failed to get step log upload url")
	}
	if !firstBlock {
		err := rs.CreateAppendFileAsync(ctx, uploadUrlResponse.LogsUrl, uploadUrlResponse.BlobStorageType)
		if err != nil {
			return err
		}
	}
	err = rs.UploadAppendFileAsync(ctx, uploadUrlResponse.LogsUrl, uploadUrlResponse.BlobStorageType, fileContent, finalize, fileSize)
	if err != nil {
		return err
	}
	if finalize {
		timestamp := time.Now().UTC().Format(TimestampOutputFormat)
		req := &JobLogsMetadataCreate{
			WorkflowJobRunBackendId: jobId,
			WorkflowRunBackendId:    planId,
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
	ResultsProtoApiV1Endpoint    = "twirp/github.actions.results.api.v1.WorkflowStepUpdateService/"
	WorkflowStepsUpdate          = ResultsProtoApiV1Endpoint + "WorkflowStepsUpdate"

	AzureBlobSealedHeader = "x-ms-blob-sealed"
	AzureBlobTypeHeader   = "x-ms-blob-type"
	AzureBlockBlob        = "BlockBlob"
	AzureAppendBlob       = "AppendBlob"
)
