package actionsrunner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	runservice "github.com/ChristopherHX/github-act-runner/protocol/run"
	"github.com/ChristopherHX/github-act-runner/runnerconfiguration"
	"github.com/sirupsen/logrus"
)

type RunRunner struct {
	Once     bool
	Trace    bool
	Version  string
	Settings *runnerconfiguration.RunnerSettings
}

type JobRun struct {
	RequestID       int64
	JobID           string
	Plan            *protocol.TaskOrchestrationPlanReference
	Name            string
	RegistrationURL string
	RunServiceURL   string
}

type RunnerEnvironment interface {
	BasicLogger
	ReadJson(fname string, obj interface{}) error
	WriteJson(fname string, obj interface{}) error
	Remove(fname string) error
	ExecWorker(run *RunRunner, wc WorkerContext, jobreq *protocol.AgentJobRequestMessage, src []byte) error
}

func (run *RunRunner) Run(runnerenv RunnerEnvironment, listenerctx context.Context, corectx context.Context) error {
	settings := run.Settings
	for i := 0; i < len(settings.Instances); i++ {
		if settings.Instances[i].PKey == nil {
			key, err := base64.StdEncoding.DecodeString(settings.Instances[i].Key)
			if err != nil {
				return err
			}
			pkey, err := x509.ParsePKCS1PrivateKey(key)
			if err != nil {
				return err
			}
			settings.Instances[i].PKey = pkey
		}
	}
	ctx, cancel := context.WithCancel(corectx)
	defer cancel()
	// This is used to wait for possible multiple jobs, they would execute sequentially and we need to wait for all
	var joblock sync.Mutex
	var jobCompletedWG sync.WaitGroup
	allJobsDone := func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			jobCompletedWG.Wait()
			close(ch)
		}()
		return ch
	}
	defer func() {
		<-allJobsDone()
	}()
	firstJobReceived := false
	go func() {
		select {
		case <-ctx.Done():
		case <-listenerctx.Done():
			select {
			case <-allJobsDone():
				cancel()
			case <-time.After(100 * time.Millisecond):
				run.Once = true
				firstJobReceived = true
			}
		}
	}()
	if len(settings.Instances) <= 0 {
		return fmt.Errorf("please configure the runner")
	}
	isEphemeral := len(settings.Instances) == 1 && settings.Instances[0].Agent.Ephemeral
	// isEphemeral => run.Once
	run.Once = run.Once || isEphemeral
	defer func() {
		if firstJobReceived && isEphemeral {
			if err := runnerenv.Remove("settings.json"); err != nil {
				runnerenv.Printf("Warning: Cannot delete settings.json after ephemeral exit: %v\n", err.Error())
			}
			if err := runnerenv.Remove("sessions.json"); err != nil {
				runnerenv.Printf("Warning: Cannot delete sessions.json after ephemeral exit: %v\n", err.Error())
			}
		}
	}()
	var sessions []*protocol.TaskAgentSession
	if err := runnerenv.ReadJson("sessions.json", &sessions); err != nil && run.Trace {
		runnerenv.Printf("sessions.json is corrupted or does not exist: %v\n", err.Error())
	}
	{
		// Backward compatibility
		var session protocol.TaskAgentSession
		if err := runnerenv.ReadJson("session.json", &session); err != nil {
			if run.Trace {
				runnerenv.Printf("session.json is corrupted or does not exist: %v\n", err.Error())
			}
		} else {
			sessions = append(sessions, &session)
			// Save new format
			runnerenv.WriteJson("sessions.json", sessions)
			// Cleanup old files
			if err := runnerenv.Remove("session.json"); err != nil {
				runnerenv.Printf("Warning: Cannot delete session.json: %v\n", err.Error())
			}
		}
	}

	firstRun := true

	for {
		mu := &sync.Mutex{}
		joblisteningctx, cancelJobListening := context.WithCancel(ctx)
		defer cancelJobListening()
		wg := new(sync.WaitGroup)
		wg.Add(len(settings.Instances))
		deleteSessions := firstRun
		firstRun = false
		// No retry on Fatal failures, like runner was removed or we received multiple jobs
		fatalFailure := false
		for _, instance := range settings.Instances {
			go func(instance *runnerconfiguration.RunnerInstance) (exitcode int) {
				defer wg.Done()
				defer func() {
					// Without this the inner return 1 got lost and we would retry it
					if exitcode != 0 {
						fatalFailure = true
					}
				}()
				customTransport := http.DefaultTransport.(*http.Transport).Clone()
				customTransport.MaxIdleConns = 1
				customTransport.IdleConnTimeout = 100 * time.Second
				if v, ok := common.LookupEnvBool("SKIP_TLS_CERT_VALIDATION"); ok && v {
					customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				}
				vssConnection := &protocol.VssConnection{
					Client: &http.Client{
						Timeout:   100 * time.Second,
						Transport: customTransport,
					},
					TenantURL: instance.Auth.TenantURL,
					PoolID:    instance.PoolID,
					TaskAgent: instance.Agent,
					Key:       instance.PKey,
					Trace:     run.Trace,
				}
				jobrun := &JobRun{}
				if runnerenv.ReadJson("jobrun.json", jobrun) == nil && ((jobrun.RegistrationURL == instance.RegistrationURL && jobrun.Name == instance.Agent.Name) || (len(settings.Instances) == 1)) {
					result := "Failed"
					finish := &protocol.JobEvent{
						Name:      "JobCompleted",
						JobID:     jobrun.JobID,
						RequestID: jobrun.RequestID,
						Result:    result,
					}
					go func() {
						for i := 0; ; i++ {
							if err := vssConnection.FinishJob(finish, jobrun.Plan); err != nil {
								runnerenv.Printf("Failed to finish previous stuck job with Status Failed: %v\n", err.Error())
							} else {
								runnerenv.Printf("Finished previous stuck job with Status Failed\n")
								break
							}
							if i < 10 {
								runnerenv.Printf("Retry finishing the job in 10 seconds attempt %v of 10\n", i+1)
								<-time.After(time.Second * 10)
							} else {
								break
							}
						}
					}()
					runnerenv.Remove("jobrun.json")
				}
				mu.Lock()
				var _session *protocol.AgentMessageConnection = nil
				for _, session := range sessions {
					if session.Agent.Name == instance.Agent.Name && session.Agent.Authorization.PublicKey == instance.Agent.Authorization.PublicKey {
						session, err := vssConnection.LoadSession(joblisteningctx, session)
						if deleteSessions {
							session.Delete(joblisteningctx)
							for i, _session := range sessions {
								if session.TaskAgentSession.SessionID == _session.SessionID {
									sessions[i] = sessions[len(sessions)-1]
									sessions = sessions[:len(sessions)-1]
								}
							}
							_ = runnerenv.WriteJson("sessions.json", sessions)
						} else if err == nil {
							_session = session
						}
					}
				}
				mu.Unlock()
				var session *protocol.AgentMessageConnection
				if _session != nil {
					session = _session
				}
				deleteSession := func() {
					if session != nil {
						timeout, cancelT := context.WithTimeout(context.Background(), time.Minute)
						defer cancelT()
						if err := session.Delete(timeout); err != nil {
							runnerenv.Printf("WARNING: Failed to delete active session: %v\n", err)
						} else {
							mu.Lock()
							for i, _session := range sessions {
								if session.TaskAgentSession.SessionID == _session.SessionID {
									sessions[i] = sessions[len(sessions)-1]
									sessions = sessions[:len(sessions)-1]
								}
							}
							runnerenv.WriteJson("sessions.json", sessions)
							session = nil
							mu.Unlock()
						}
					}
				}
				defer deleteSession()
				xctx, _c := context.WithCancel(joblisteningctx)
				lastSuccess := time.Now()
				defer _c()
				for {
					message := &protocol.TaskAgentMessage{}
					success := false
					for !success {
						select {
						case <-joblisteningctx.Done():
							return 0
						default:
						}
						if session == nil || time.Now().After(lastSuccess.Add(5*time.Minute)) {
							deleteSession()
							session2, err := vssConnection.CreateSession(joblisteningctx)
							if err != nil {
								if strings.Contains(err.Error(), "invalid_client") || strings.Contains(err.Error(), "TaskAgentNotFoundException") {
									runnerenv.Printf("Fatal: It seems this runner was removed from GitHub, Failed to recreate Session for %v ( %v ): %v\n", instance.Agent.Name, instance.RegistrationURL, err.Error())
									return 1
								}
								runnerenv.Printf("Failed to recreate Session for %v ( %v ), waiting 30 sec before retry: %v\n", instance.Agent.Name, instance.RegistrationURL, err.Error())
								select {
								case <-joblisteningctx.Done():
									return 0
								case <-time.After(30 * time.Second):
								}
								continue
							} else if session2 != nil {
								session = session2
								mu.Lock()
								sessions = append(sessions, session.TaskAgentSession)
								err := runnerenv.WriteJson("sessions.json", sessions)
								if err != nil {
									runnerenv.Printf("error: %v\n", err)
								} else {
									runnerenv.Printf("Listening for Jobs: %v ( %v )\n", instance.Agent.Name, instance.RegistrationURL)
								}
								mu.Unlock()
							} else {
								runnerenv.Printf("Failed to recreate Session, waiting 30 sec before retry\n")
								select {
								case <-joblisteningctx.Done():
									return 0
								case <-time.After(30 * time.Second):
								}
								continue
							}
						}
						err := vssConnection.RequestWithContext(xctx, "c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "GET", map[string]string{
							"poolId": fmt.Sprint(instance.PoolID),
						}, map[string]string{
							"sessionId": session.TaskAgentSession.SessionID,
						}, nil, message)
						//TODO lastMessageId=
						if err != nil {
							if errors.Is(err, context.Canceled) {
								return 0
							} else if !errors.Is(err, io.EOF) {
								if strings.Contains(err.Error(), "TaskAgentSessionExpiredException") {
									runnerenv.Printf("Failed to get message, Session expired: %v\n", err.Error())
									session = nil
									continue
								} else if strings.Contains(err.Error(), "AccessDeniedException") {
									runnerenv.Printf("Failed to get message, GitHub has rejected our authorization, recreate Session earlier: %v\n", err.Error())
									session = nil
									continue
								} else {
									runnerenv.Printf("Failed to get message, waiting 10 sec before retry: %v\n", err.Error())
									select {
									case <-joblisteningctx.Done():
										return 0
									case <-time.After(10 * time.Second):
									}
								}
							} else {
								lastSuccess = time.Now()
							}
						} else {
							lastSuccess = time.Now()
							if firstJobReceived && (strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") || strings.EqualFold(message.MessageType, "RunnerJobRequest")) {
								// It seems run once isn't supported by the backend, do the same as the official runner
								// Skip deleting the job message and cancel earlier
								runnerenv.Printf("Received a second job, but running in run once mode abort\n")
								return 1
							}
							success = true
							err := vssConnection.Request("c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "DELETE", map[string]string{
								"poolId":    fmt.Sprint(instance.PoolID),
								"messageId": fmt.Sprint(message.MessageID),
							}, map[string]string{
								"sessionId": session.TaskAgentSession.SessionID,
							}, nil, nil)
							if err != nil {
								runnerenv.Printf("Failed to delete Message\n")
								success = false
							}
						}
					}
					if success {
						if message != nil && (strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") || strings.EqualFold(message.MessageType, "RunnerJobRequest")) {
							cancelJobListening()
							for message != nil && !firstJobReceived && (strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") || strings.EqualFold(message.MessageType, "RunnerJobRequest")) {
								if run.Once {
									firstJobReceived = true
								}
								jobctx, finishJob := context.WithCancel(context.Background())
								jobExecCtx, cancelJob := context.WithCancel(ctx)
								jobCompletedWG.Add(1)
								go func() {
									<-jobctx.Done()
									jobCompletedWG.Done()
								}()
								runJob(runnerenv, &joblock, vssConnection, run, cancel, cancelJob, finishJob, jobExecCtx, jobctx, session, *message, instance)
								{
									var err error
									message, err = session.GetNextMessage(jobExecCtx)
									if !errors.Is(err, context.Canceled) && message != nil {
										if firstJobReceived && (strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") || strings.EqualFold(message.MessageType, "RunnerJobRequest")) {
											runnerenv.Printf("Skip deleting the duplicated job request, we hope that the actions service reschedules your job to a different runner\n")
										} else {
											session.DeleteMessage(joblisteningctx, message)
										}
										if strings.EqualFold(message.MessageType, "JobCancellation") && cancelJob != nil {
											message = nil
											runnerenv.Printf("JobCancellation request received, cancel running job\n")
											cancelJob()
										} else {
											runnerenv.Printf("Received message, while still executing a job, of type: %v\n", message.MessageType)
										}
										runnerenv.Printf("Wait for worker to finish current job\n")
										<-jobctx.Done()
									}
								}
							}
							// Skip deleting session for ephemeral, since the official actions service throws access denied
							if !run.Once || isEphemeral {
								session = nil
							}
						}
						if message != nil {
							runnerenv.Printf("Ignoring incoming message of type: %v\n", message.MessageType)
						}
					}
				}
			}(instance)
		}
		wg.Wait()
		if fatalFailure {
			return fmt.Errorf("fatal error, see log")
		}
		select {
		case <-allJobsDone():
			if run.Once {
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}

type RunnerJobRequestRef struct {
	Id              string `json:"id"`
	RunnerRequestId string `json:"runner_request_id"`
	RunServiceUrl   string `json:"run_service_url"`
}

type plainTextFormatter struct {
}

func (f *plainTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Time.UTC().Format(protocol.TimestampOutputFormat) + " " + entry.Message + "\n"), nil
}

func runJob(runnerenv RunnerEnvironment, joblock *sync.Mutex, vssConnection *protocol.VssConnection, run *RunRunner, cancel context.CancelFunc, cancelJob context.CancelFunc, finishJob context.CancelFunc, jobExecCtx context.Context, jobctx context.Context, session *protocol.AgentMessageConnection, message protocol.TaskAgentMessage, instance *runnerconfiguration.RunnerInstance) {
	go func() {
		plogger := &PrefixConsoleLogger{
			Parent: runnerenv,
			Prefix: fmt.Sprintf("%v ( %v ):", instance.Agent.Name, instance.RegistrationURL),
		}
		defer func() {
			if run.Once {
				// cancel Message Loop
				plogger.Printf("Last Job finished, cancel Message loop\n")
				cancel()
			}
			cancelJob()
			finishJob()
		}()
		src, err := message.Decrypt(session.Block)
		if err != nil {
			plogger.Printf("Failed to decode TaskAgentMessage: %v\n", err)
			return
		}
		if run.Trace {
			plogger.Printf("%v\n", string(src))
		}
		jobreq := &protocol.AgentJobRequestMessage{}
		var runServiceUrl string
		{
			if strings.EqualFold(message.MessageType, "RunnerJobRequest") {
				rjrr := &RunnerJobRequestRef{}
				json.Unmarshal(src, rjrr)
				for retries := 0; retries < 5; retries++ {
					var err error
					if len(rjrr.RunServiceUrl) == 0 {
						err = vssConnection.RequestWithContext(jobctx, "25adab70-1379-4186-be8e-b643061ebe3a", "6.0-preview", "GET", map[string]string{
							"messageId": rjrr.RunnerRequestId,
						}, map[string]string{}, nil, &src)
					} else {
						copy := *vssConnection
						vssConnection = &copy
						runServiceUrl = rjrr.RunServiceUrl
						acquirejobUrl, _ := url.Parse(runServiceUrl)
						acquirejobUrl.Path = path.Join(acquirejobUrl.Path, "acquirejob")
						vssConnection.TenantURL = runServiceUrl
						payload := &runservice.AcquireJobRequest{
							StreamID:     rjrr.RunnerRequestId,
							JobMessageID: rjrr.RunnerRequestId,
						}
						err = vssConnection.RequestWithContext2(jobctx, "POST", acquirejobUrl.String(), "", payload, &src)
					}
					if err == nil {
						json.Unmarshal(src, jobreq)
						break
					}
					<-time.After(time.Second * 5 * time.Duration(retries+1))
				}
			} else {
				json.Unmarshal(src, jobreq)
			}
		}
		jobrun := &JobRun{
			RequestID:       jobreq.RequestID,
			JobID:           jobreq.JobID,
			Plan:            jobreq.Plan,
			RegistrationURL: instance.RegistrationURL,
			Name:            instance.Agent.Name,
			RunServiceURL:   runServiceUrl,
		}
		{
			// TODO multi repository runners can receive multiple job requests at the same time and this protection doesn't work there
			if err := runnerenv.WriteJson("jobrun.json", jobrun); err != nil {
				plogger.Printf("INFO: Failed to create jobrun.json: %v\n", err)
			}
		}
		con := *vssConnection
		go func() {
			for {
				var err error
				if runServiceUrl != "" {
					vssConnection = &con
					renewjobUrl, _ := url.Parse(runServiceUrl)
					renewjobUrl.Path = path.Join(renewjobUrl.Path, "renewjob")
					vssConnection.TenantURL = runServiceUrl
					payload := &runservice.RenewJobRequest{
						PlanID: jobreq.Plan.PlanID,
						JobID:  jobreq.JobID,
					}
					resp := &runservice.RenewJobResponse{}
					err = vssConnection.RequestWithContext2(jobctx, "POST", renewjobUrl.String(), "", payload, &resp)
				} else {
					err = con.RequestWithContext(jobctx, "fc825784-c92a-4299-9221-998a02d1b54f", "5.1-preview", "PATCH", map[string]string{
						"poolId":    fmt.Sprint(instance.PoolID),
						"requestId": fmt.Sprint(jobreq.RequestID),
					}, map[string]string{
						"lockToken": "00000000-0000-0000-0000-000000000000",
					}, &protocol.RenewAgent{RequestID: jobreq.RequestID}, nil)
				}
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return
					} else {
						plogger.Printf("Failed to renew job: %v\n", err.Error())
					}
				}
				select {
				case <-jobctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
			}
		}()
		plogger.Printf("Running Job '%v'\n", jobreq.JobDisplayName)
		wc := &DefaultWorkerContext{
			RunnerMessage:       jobreq,
			JobExecutionContext: jobExecCtx,
			VssConnection:       vssConnection,
			RunnerLogger:        plogger,
		}
		wc.Init()
		jlogger := wc.Logger()
		defer jlogger.Logger.Close()
		setupJobEntry := jlogger.Append(protocol.CreateTimelineEntry(jobreq.JobID, "__setup_worker", "Set up Worker"))
		setupJobEntry.Order = 0
		setupJobEntry.Start()
		jlogger.MoveNext()

		defer func() {
			if err := recover(); err != nil {
				wc.FailInitJob("Worker panicked", "The worker panicked with message: "+fmt.Sprint(err)+"\n"+string(debug.Stack()))
			}
			runnerenv.Remove("jobrun.json")
		}()

		logger := logrus.New()
		logger.SetOutput(jlogger)
		logger.SetFormatter(&plainTextFormatter{})
		logger.SetLevel(logrus.DebugLevel)

		jlogger.Update()

		logger.Log(logrus.InfoLevel, "Runner Name: "+instance.Agent.Name)
		logger.Log(logrus.InfoLevel, "Runner OSDescription: github-act-runner "+runtime.GOOS+"/"+runtime.GOARCH)
		if len(run.Version) > 0 {
			logger.Log(logrus.InfoLevel, "Runner Version: "+run.Version)
		}

		// Wait for possible concurrent running job and serialize, this only happens for multi repository runners
		waitContext, finishWait := context.WithCancel(jobExecCtx)
		defer finishWait()
		go func() {
			for {
				select {
				case <-waitContext.Done():
					return
				case <-time.After(1 * time.Second):
					logger.Log(logrus.InfoLevel, "Waiting for runner to complete active job")
				}
			}
		}()
		joblch := make(chan struct{})
		go func() {
			joblock.Lock()
			defer func() {
				joblock.Unlock()
			}()
			close(joblch)
			<-jobctx.Done()
		}()
		select {
		case <-joblch:
			finishWait()
		case <-jobExecCtx.Done():
		}
		// The following code is synchronized
		err = runnerenv.ExecWorker(run, wc, jobreq, src)
		if err != nil {
			wc.FailInitJob("Worker Failed", err.Error())
		} else {
			plogger.Printf("Finished Job '%v'\n", jobreq.JobDisplayName)
		}
	}()
}
