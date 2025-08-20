package actionsrunner

import (
	"context"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/logger"
	"github.com/ChristopherHX/github-act-runner/protocol/run"
)

// Constants for worker context retry logic
const (
	workerMaxRetryAttempts = 10
	workerRetry            = 10 * time.Second
)

type WorkerContext interface {
	FinishJob(result string, outputs *map[string]protocol.VariableValue)
	FailInitJob(title string, message string)
	Message() *protocol.AgentJobRequestMessage
	Logger() *logger.JobLogger
	JobExecCtx() context.Context
}

type DefaultWorkerContext struct {
	RunnerMessage       *protocol.AgentJobRequestMessage
	JobLogger           *logger.JobLogger
	JobExecutionContext context.Context
	VssConnection       *protocol.VssConnection
	RunnerLogger        BasicLogger
}

// FinishJob completes the job execution with the given result and outputs
//
//nolint:gocritic // ptrToRefParam: API compatibility requirement - changing pointer to value would be breaking change
func (wc *DefaultWorkerContext) FinishJob(result string, outputs *map[string]protocol.VariableValue) {
	if strings.EqualFold(wc.Message().MessageType, "RunnerJobRequest") {
		payload := &run.CompleteJobRequest{
			PlanID:         wc.Message().Plan.PlanID,
			JobID:          wc.Message().JobID,
			Conclusion:     strings.ToLower(result),
			Outputs:        nil,
			BillingOwnerID: wc.Message().BillingOwnerID,
		}
		if outputs != nil {
			payload.Outputs = *outputs
		}
		recs := wc.Logger().TimelineRecords
		if recs != nil {
			stepResults := []run.StepResult{}
			for i, rec := range recs.Value {
				if i == 0 {
					annotations := make([]run.Annotation, len(rec.Issues))
					for i, issue := range rec.Issues {
						annotations[i] = run.IssueToAnnotation(issue)
					}
					payload.Annotations = annotations
				} else if rec != nil {
					stepResults = append(stepResults, run.TimeLineRecordToStepResult(rec))
				}
			}
			payload.StepResults = stepResults
		}

		completejobURL, _ := url.Parse(wc.VssConnection.TenantURL)
		completejobURL.Path = path.Join(completejobURL.Path, "completejob")
		for i := 0; ; i++ {
			if err := wc.VssConnection.RequestWithContext2(context.Background(), "POST", completejobURL.String(), "", payload, nil); err != nil {
				wc.RunnerLogger.Printf("Failed to finish Job '%v' with Status %v: %v\n", wc.Message().JobDisplayName, result, err.Error())
			} else {
				wc.RunnerLogger.Printf("Finished Job '%v' with Status %v\n", wc.Message().JobDisplayName, result)
				break
			}
			if i < workerMaxRetryAttempts {
				wc.RunnerLogger.Printf("Retry finishing '%v' in %d seconds attempt %v of %d\n",
					wc.Message().JobDisplayName, workerRetry/time.Second, i+1, workerMaxRetryAttempts)
				<-time.After(workerRetry)
			} else {
				break
			}
		}
		return
	}
	finish := &protocol.JobEvent{
		Name:      "JobCompleted",
		JobID:     wc.Message().JobID,
		RequestID: wc.Message().RequestID,
		Result:    result,
		Outputs:   outputs,
	}
	for i := 0; ; i++ {
		if err := wc.VssConnection.FinishJob(finish, wc.Message().Plan); err != nil {
			wc.RunnerLogger.Printf("Failed to finish Job '%v' with Status %v: %v\n", wc.Message().JobDisplayName, result, err.Error())
		} else {
			wc.RunnerLogger.Printf("Finished Job '%v' with Status %v\n", wc.Message().JobDisplayName, result)
			break
		}
		if i < workerMaxRetryAttempts {
			wc.RunnerLogger.Printf("Retry finishing '%v' in %d seconds attempt %v of %d\n",
				wc.Message().JobDisplayName, workerRetry/time.Second, i+1, workerMaxRetryAttempts)
			<-time.After(workerRetry)
		} else {
			break
		}
	}
}

func (wc *DefaultWorkerContext) FailInitJob(title, message string) {
	if wc.Logger().Current() != nil {
		wc.Logger().Current().Complete("Failed")
	}
	timelineEntry := protocol.CreateTimelineEntry(wc.Message().JobID, "__fatal", title)
	e := wc.Logger().Append(&timelineEntry)
	e.Start()
	if wc.Logger().Current() != e {
		for {
			next := wc.Logger().MoveNext()
			if next == nil || next == e {
				break
			}
			wc.Logger().Current().Complete("Skipped")
		}
	}
	wc.Logger().Log(message)
	e.Complete("Failed")
	_ = wc.Logger().Logger.Close() // Ignore logger close errors
	wc.Logger().MoveNext()
	wc.Logger().TimelineRecords.Value[0].Complete("Failed")
	wc.Logger().Finish()
	wc.FinishJob("Failed", &map[string]protocol.VariableValue{})
}

func (wc *DefaultWorkerContext) Message() *protocol.AgentJobRequestMessage {
	return wc.RunnerMessage
}

func (wc *DefaultWorkerContext) Logger() *logger.JobLogger {
	return wc.JobLogger
}

func (wc *DefaultWorkerContext) JobExecCtx() context.Context {
	return wc.JobExecutionContext
}

func (wc *DefaultWorkerContext) Init() {
	jobVssConnection, vssConnectionData, err := wc.Message().GetConnection("SystemVssConnection")
	if err != nil {
		wc.RunnerLogger.Printf("Failed to find the SystemVssConnection Endpoint, try to finish job as failed")
		wc.FinishJob("Failed", &map[string]protocol.VariableValue{})
		return
	}
	if wc.VssConnection != nil {
		jobVssConnection.Client = wc.VssConnection.Client
		jobVssConnection.Trace = wc.VssConnection.Trace
	}
	wc.VssConnection = jobVssConnection

	jobreq := wc.Message()
	resultsEndpoint, hasResultsEndpoint := jobreq.Variables["system.github.results_endpoint"]
	wc.JobLogger = &logger.JobLogger{
		JobRequest:      jobreq,
		Connection:      jobVssConnection,
		TimelineRecords: &protocol.TimelineRecordWrapper{},
	}

	if hasResultsEndpoint && strings.EqualFold(jobreq.MessageType, "RunnerJobRequest") {
		wc.JobLogger.IsResults = true
		con := *jobVssConnection
		con.TenantURL = resultsEndpoint.Value
		wc.JobLogger.ResultsConnection = &con
		wc.JobLogger.Logger = &logger.BufferedLiveLogger{
			LiveLogger: &logger.WebsocketLiveloggerWithFallback{
				JobRequest:    jobreq,
				Connection:    jobVssConnection,
				FeedStreamURL: vssConnectionData["FeedStreamUrl"],
				ForceWebsock:  true,
			},
		}
	} else {
		if hasResultsEndpoint {
			con := *jobVssConnection
			con.TenantURL = resultsEndpoint.Value
			wc.JobLogger.ResultsConnection = &con
		}
		wc.JobLogger.Logger = &logger.BufferedLiveLogger{
			LiveLogger: &logger.WebsocketLiveloggerWithFallback{
				JobRequest:    jobreq,
				Connection:    jobVssConnection,
				FeedStreamURL: vssConnectionData["FeedStreamUrl"],
			},
		}
	}
	timelineEntry := protocol.CreateTimelineEntry("", wc.Message().JobName, wc.Message().JobDisplayName)
	jobEntry := wc.Logger().Append(&timelineEntry)
	jobEntry.ID = wc.Message().JobID
	jobEntry.Type = "Job"
	jobEntry.Order = 0
	jobEntry.Start()
}
