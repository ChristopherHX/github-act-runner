package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ChristopherHX/github-act-runner/actionsdotnetactcompat"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/runnerconfiguration"
	"golang.org/x/net/websocket"

	// "github.com/AlecAivazis/survey/v2"

	"github.com/google/uuid"
	_ "github.com/mtibben/androiddnsfix"
	"github.com/nektos/act/pkg/common"
	"github.com/nektos/act/pkg/container"
	"github.com/nektos/act/pkg/model"
	"github.com/nektos/act/pkg/runner"
	"github.com/robertkrimen/otto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type ghaFormatter struct {
	rqt            *protocol.AgentJobRequestMessage
	rc             *runner.RunContext
	wrap           *protocol.TimelineRecordWrapper
	current        *protocol.TimelineRecord
	updateTimeLine func()
	logline        func(startLine int64, recordId string, lines []string)
	uploadLogFile  func(log string) int
	startLine      int64
	stepBuffer     *bytes.Buffer
	linefeedregex  *regexp.Regexp
}

func (f *ghaFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}

	if f.rc.Parent == nil && (f.current == nil || f.current.RefName != f.rc.CurrentStep) {
		res, ok := f.rc.StepResults[f.current.RefName]
		if ok {
			f.startLine = 1
			if f.current != nil {
				if res.Conclusion == model.StepStatusSuccess {
					f.current.Complete("Succeeded")
				} else if res.Conclusion == model.StepStatusSkipped {
					f.current.Complete("Skipped")
				} else {
					f.current.Complete("Failed")
				}
				if f.stepBuffer.Len() > 0 {
					f.current.Log = &protocol.TaskLogReference{ID: f.uploadLogFile(f.stepBuffer.String())}
				}
			}
			f.stepBuffer = &bytes.Buffer{}
			for i := range f.wrap.Value {
				if f.wrap.Value[i].RefName == f.rc.CurrentStep {
					f.current = &f.wrap.Value[i]
					f.current.Start()
					break
				}
			}
			f.updateTimeLine()
		}
	}
	if f.rqt.MaskHints != nil {
		for _, v := range f.rqt.MaskHints {
			if strings.ToLower(v.Type) == "regex" {
				r, _ := regexp.Compile(v.Value)
				entry.Message = r.ReplaceAllString(entry.Message, "***")
			}
		}
	}
	if f.rqt.Variables != nil {
		for _, v := range f.rqt.Variables {
			if v.IsSecret && len(v.Value) > 0 {
				entry.Message = strings.ReplaceAll(entry.Message, v.Value, "***")
			}
		}
	}

	if f.linefeedregex == nil {
		f.linefeedregex = regexp.MustCompile(`(\r\n|\r|\n)`)
	}

	prefix := ""
	if entry.Level == logrus.DebugLevel {
		prefix = "##[debug]"
	} else if entry.Level == logrus.WarnLevel {
		prefix = "##[warning]"
	} else if entry.Level == logrus.ErrorLevel {
		prefix = "##[error]"
	}
	entry.Message = f.linefeedregex.ReplaceAllString(prefix+strings.Trim(entry.Message, "\r\n"), "\n"+prefix)

	b.WriteString(entry.Message)
	b.WriteByte('\n')
	lines := strings.Split(entry.Message, "\n")
	f.logline(f.startLine, f.current.ID, lines)
	f.startLine += int64(len(lines))
	f.stepBuffer.Write(b.Bytes())
	return b.Bytes(), nil
}

func WriteJson(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, 0777)
}

func ReadJson(path string, value interface{}) error {
	cont, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(cont, value)
}

type RunRunner struct {
	Once     bool
	Terminal bool
	Trace    bool
}

type JobRun struct {
	RequestID       int64
	JobID           string
	Plan            *protocol.TaskOrchestrationPlanReference
	Name            string
	RegistrationURL string
}

func readLegacyInstance(settings *runnerconfiguration.RunnerSettings, instance *runnerconfiguration.RunnerInstance) int {
	taskAgent := &protocol.TaskAgent{}
	var key *rsa.PrivateKey
	req := &protocol.GitHubAuthResult{}
	{
		cont, err := ioutil.ReadFile("agent.json")
		if err != nil {
			return 1
		}
		err = json.Unmarshal(cont, taskAgent)
		if err != nil {
			return 1
		}
	}
	{
		cont, err := ioutil.ReadFile("cred.pkcs1")
		if err != nil {
			return 1
		}
		key, err = x509.ParsePKCS1PrivateKey(cont)
		if err != nil {
			return 1
		}
	}
	{
		cont, err := ioutil.ReadFile("auth.json")
		if err != nil {
			return 1
		}
		err = json.Unmarshal(cont, req)
		if err != nil {
			return 1
		}
	}
	instance.Agent = taskAgent
	instance.PKey = key
	instance.PoolID = settings.PoolID
	instance.RegistrationURL = settings.RegistrationURL
	instance.Auth = req
	return 0
}

func loadConfiguration() (*runnerconfiguration.RunnerSettings, error) {
	settings := &runnerconfiguration.RunnerSettings{}
	{
		cont, err := ioutil.ReadFile("settings.json")
		if err != nil {
			// Backward compat <= 0.0.3
			// fmt.Printf("The runner needs to be configured first: %v\n", err.Error())
			// return 1
			settings.PoolID = 1
		} else {
			err = json.Unmarshal(cont, settings)
			if err != nil {
				return nil, err
			}
		}
	}
	{
		for i := 0; i < len(settings.Instances); i++ {
			key, _ := base64.StdEncoding.DecodeString(settings.Instances[i].Key)
			pkey, _ := x509.ParsePKCS1PrivateKey(key)
			settings.Instances[i].PKey = pkey
		}
		instance := &runnerconfiguration.RunnerInstance{}
		if readLegacyInstance(settings, instance) == 0 {
			settings.Instances = append(settings.Instances, instance)
		}
	}
	return settings, nil
}

func containsEphemeralConfiguration() bool {
	settings, err := loadConfiguration()
	if err != nil || settings == nil {
		return false
	}
	for _, instance := range settings.Instances {
		if instance.Agent != nil && instance.Agent.Ephemeral {
			return true
		}
	}
	return false
}

func (run *RunRunner) Run() int {
	// This is used to wait for possible multiple jobs, they would execute sequentially and we need to wait for all
	var jobCompletedWG sync.WaitGroup
	allJobsDone := func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			jobCompletedWG.Wait()
			close(ch)
		}()
		return ch
	}
	container.SetContainerAllocateTerminal(run.Terminal)
	// trap Ctrl+C
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGTERM, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())
	firstJobReceived := false
	go func() {
		sig := <-channel
		if sig == syscall.SIGTERM {
			select {
			case <-allJobsDone():
				fmt.Println("SIGTERM received, no job is running shutdown")
			case <-time.After(100 * time.Millisecond):
				fmt.Println("SIGTERM received, cancel the current job and wait for completion")
			}
			cancel()
		} else {
			select {
			case <-allJobsDone():
				fmt.Println("CTRL+C received, no job is running shutdown")
				cancel()
			case <-time.After(100 * time.Millisecond):
				fmt.Println("CTRL+C received, stop accepting new jobs and exit after the current job finishes")
				// Switch to run once mode
				run.Once = true
				firstJobReceived = true
			}
			select {
			case <-ctx.Done():
				return
			case <-channel:
				fmt.Println("CTRL+C received again, cancel current Job if it is still running")
				cancel()
			}
		}
	}()
	defer func() {
		cancel()
		signal.Stop(channel)
	}()
	defer func() {
		<-allJobsDone()
	}()
	settings, err := loadConfiguration()
	if err != nil {
		fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
		return 1
	}
	if len(settings.Instances) <= 0 {
		fmt.Printf("Please configure the runner")
		return 1
	}
	isEphemeral := len(settings.Instances) == 1 && settings.Instances[0].Agent.Ephemeral
	// isEphemeral => run.Once
	run.Once = run.Once || isEphemeral
	defer func() {
		if firstJobReceived && isEphemeral {
			if err := os.Remove("settings.json"); err != nil {
				fmt.Printf("Warning: Cannot delete settings.json after ephemeral exit: %v\n", err.Error())
			}
			if err := os.Remove("sessions.json"); err != nil {
				fmt.Printf("Warning: Cannot delete sessions.json after ephemeral exit: %v\n", err.Error())
			}
		}
	}()
	var sessions []*protocol.TaskAgentSession
	if err := ReadJson("sessions.json", &sessions); err != nil && run.Trace {
		fmt.Printf("sessions.json is corrupted or does not exist: %v\n", err.Error())
	}
	{
		// Backward compatibility
		var session protocol.TaskAgentSession
		if err := ReadJson("session.json", &session); err != nil {
			if run.Trace {
				fmt.Printf("session.json is corrupted or does not exist: %v\n", err.Error())
			}
		} else {
			sessions = append(sessions, &session)
			// Save new format
			WriteJson("sessions.json", sessions)
			// Cleanup old files
			if err := os.Remove("session.json"); err != nil {
				fmt.Printf("Warning: Cannot delete session.json: %v\n", err.Error())
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
				vssConnection := &protocol.VssConnection{
					Client: &http.Client{
						Timeout: 100 * time.Second,
						Transport: &http.Transport{
							MaxIdleConns:    1,
							IdleConnTimeout: 100 * time.Second,
						},
					},
					TenantURL: instance.Auth.TenantURL,
					PoolID:    instance.PoolID,
					TaskAgent: instance.Agent,
					Key:       instance.PKey,
					Trace:     run.Trace,
				}
				jobrun := &JobRun{}
				if ReadJson("jobrun.json", jobrun) == nil && ((jobrun.RegistrationURL == instance.RegistrationURL && jobrun.Name == instance.Agent.Name) || (len(settings.Instances) == 1)) {
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
								fmt.Printf("Failed to finish previous stuck job with Status Failed: %v\n", err.Error())
							} else {
								fmt.Println("Finished previous stuck job with Status Failed")
								break
							}
							if i < 10 {
								fmt.Printf("Retry finishing the job in 10 seconds attempt %v of 10\n", i+1)
								<-time.After(time.Second * 10)
							} else {
								break
							}
						}
					}()
					os.Remove("jobrun.json")
				}
				mu.Lock()
				var _session *protocol.AgentMessageConnection = nil
				for _, session := range sessions {
					if session.Agent.Name == instance.Agent.Name && session.Agent.Authorization.PublicKey == instance.Agent.Authorization.PublicKey {
						session, err := vssConnection.LoadSession(session)
						if deleteSessions {
							session.Delete()
							for i, _session := range sessions {
								if session.TaskAgentSession.SessionID == _session.SessionID {
									sessions[i] = sessions[len(sessions)-1]
									sessions = sessions[:len(sessions)-1]
								}
							}
							WriteJson("sessions.json", sessions)
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
						if err := session.Delete(); err != nil {
							fmt.Printf("WARNING: Failed to delete active session: %v\n", err)
						} else {
							mu.Lock()
							for i, _session := range sessions {
								if session.TaskAgentSession.SessionID == _session.SessionID {
									sessions[i] = sessions[len(sessions)-1]
									sessions = sessions[:len(sessions)-1]
								}
							}
							WriteJson("sessions.json", sessions)
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
							session2, err := vssConnection.CreateSession()
							if err != nil {
								if strings.Contains(err.Error(), "invalid_client") || strings.Contains(err.Error(), "TaskAgentNotFoundException") {
									fmt.Printf("Fatal: It seems this runner was removed from GitHub, Failed to recreate Session for %v ( %v ): %v\n", instance.Agent.Name, instance.RegistrationURL, err.Error())
									return 1
								}
								fmt.Printf("Failed to recreate Session for %v ( %v ), waiting 30 sec before retry: %v\n", instance.Agent.Name, instance.RegistrationURL, err.Error())
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
								err := WriteJson("sessions.json", sessions)
								if err != nil {
									fmt.Printf("error: %v\n", err)
								} else {
									fmt.Printf("Listening for Jobs: %v ( %v )\n", instance.Agent.Name, instance.RegistrationURL)
								}
								mu.Unlock()
							} else {
								fmt.Println("Failed to recreate Session, waiting 30 sec before retry")
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
									fmt.Printf("Failed to get message, Session expired: %v\n", err.Error())
									session = nil
									continue
								} else if strings.Contains(err.Error(), "AccessDeniedException") {
									fmt.Printf("Failed to get message, GitHub has rejected our authorization, recreate Session earlier: %v\n", err.Error())
									session = nil
									continue
								} else {
									fmt.Printf("Failed to get message, waiting 10 sec before retry: %v\n", err.Error())
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
								fmt.Println("Received a second job, but running in run once mode abort")
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
								fmt.Println("Failed to delete Message")
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
								runJob(vssConnection, run, cancel, cancelJob, finishJob, jobExecCtx, jobctx, session, *message, instance)
								{
									message, err = session.GetNextMessage(jobExecCtx)
									if !errors.Is(err, context.Canceled) && message != nil {
										if firstJobReceived && (strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") || strings.EqualFold(message.MessageType, "RunnerJobRequest")) {
											fmt.Println("Skip deleting the duplicated job request, we hope that the actions service reschedules your job to a different runner")
										} else {
											session.DeleteMessage(message)
										}
										if strings.EqualFold(message.MessageType, "JobCancellation") && cancelJob != nil {
											message = nil
											fmt.Println("JobCancellation request received, cancel running job")
											cancelJob()
										} else {
											fmt.Println("Received message, while still executing a job, of type: " + message.MessageType)
										}
										fmt.Println("Wait for worker to finish current job")
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
							fmt.Println("Ignoring incoming message of type: " + message.MessageType)
						}
					}
				}
			}(instance)
		}
		wg.Wait()
		if fatalFailure {
			return 1
		}
		select {
		case <-allJobsDone():
			if run.Once {
				return 0
			}
		case <-ctx.Done():
			return 0
		}
	}
}

type RunnerJobRequestRef struct {
	Id              string `json:"id"`
	RunnerRequestId string `json:"runner_request_id"`
}

var joblock sync.Mutex

func runJob(vssConnection *protocol.VssConnection, run *RunRunner, cancel context.CancelFunc, cancelJob context.CancelFunc, finishJob context.CancelFunc, jobExecCtx context.Context, jobctx context.Context, session *protocol.AgentMessageConnection, message protocol.TaskAgentMessage, instance *runnerconfiguration.RunnerInstance) {
	go func() {
		defer func() {
			if run.Once {
				// cancel Message Loop
				fmt.Println("Last Job finished, cancel Message loop")
				cancel()
			}
			cancelJob()
			finishJob()
		}()
		src, err := message.Decrypt(session.Block)
		if err != nil {
			fmt.Printf("Failed to decode TaskAgentMessage: %v\n", err)
			return
		}
		if run.Trace {
			fmt.Println(string(src))
		}
		jobreq := &protocol.AgentJobRequestMessage{}
		{
			if strings.EqualFold(message.MessageType, "RunnerJobRequest") {
				rjrr := &RunnerJobRequestRef{}
				json.Unmarshal(src, rjrr)
				for retries := 0; retries < 5; retries++ {
					err := vssConnection.Request("25adab70-1379-4186-be8e-b643061ebe3a", "6.0-preview", "GET", map[string]string{
						"messageId": rjrr.RunnerRequestId,
					}, map[string]string{}, nil, &src)
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
		}
		{
			if err := WriteJson("jobrun.json", jobrun); err != nil {
				fmt.Printf("INFO: Failed to create jobrun.json: %v\n", err)
			}
		}
		con := *vssConnection
		go func() {
			for {
				err := con.Request("fc825784-c92a-4299-9221-998a02d1b54f", "5.1-preview", "PATCH", map[string]string{
					"poolId":    fmt.Sprint(instance.PoolID),
					"requestId": fmt.Sprint(jobreq.RequestID),
				}, map[string]string{
					"lockToken": "00000000-0000-0000-0000-000000000000",
				}, &protocol.RenewAgent{RequestID: jobreq.RequestID}, nil)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return
					} else {
						fmt.Printf("Failed to renew job: %v\n", err.Error())
					}
				}
				select {
				case <-jobctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
			}
		}()
		fmt.Printf("Running Job '%v' of %v ( %v )\n", jobreq.JobDisplayName, instance.Agent.Name, instance.RegistrationURL)
		finishJob2 := func(result string, outputs *map[string]protocol.VariableValue) {
			finish := &protocol.JobEvent{
				Name:      "JobCompleted",
				JobID:     jobreq.JobID,
				RequestID: jobreq.RequestID,
				Result:    result,
				Outputs:   outputs,
			}
			for i := 0; ; i++ {
				if err := vssConnection.FinishJob(finish, jobrun.Plan); err != nil {
					fmt.Printf("Failed to finish Job '%v' with Status %v: %v\n", jobreq.JobDisplayName, result, err.Error())
				} else {
					fmt.Printf("Finished Job '%v' with Status %v of %v ( %v )\n", jobreq.JobDisplayName, result, instance.Agent.Name, instance.RegistrationURL)
					break
				}
				if i < 10 {
					fmt.Printf("Retry finishing '%v' in 10 seconds attempt %v of 10\n", jobreq.JobDisplayName, i+1)
					<-time.After(time.Second * 10)
				} else {
					break
				}
			}
			os.Remove("jobrun.json")
		}
		finishJob := func(result string) {
			finishJob2(result, nil)
		}
		rqt := jobreq
		secrets := map[string]string{}
		if rqt.Variables != nil {
			for k, v := range rqt.Variables {
				if v.IsSecret && k != "system.github.token" {
					secrets[k] = v.Value
				}
			}
			if rawGithubToken, ok := rqt.Variables["system.github.token"]; ok {
				secrets["GITHUB_TOKEN"] = rawGithubToken.Value
			}
		}
		runnerConfig := &runner.Config{
			Secrets: secrets,
			CompositeRestrictions: &model.CompositeRestrictions{
				AllowCompositeUses:            true,
				AllowCompositeIf:              true,
				AllowCompositeContinueOnError: true,
			},
		}
		if len(instance.RunnerGuard) > 0 {
			vm := otto.New()
			{
				var req interface{}
				e := json.Unmarshal(src, &req)
				fmt.Println(e)
				vm.Set("runnerInstance", instance)
				vm.Set("jobrequest", req)
				vm.Set("jobrun", jobrun)
				vm.Set("runnerConfig", runnerConfig)
				//otto panics
				vm.Set("TemplateTokenToObject", func(p interface{}) interface{} {
					val, err := vm.Call("JSON.stringify", nil, p)
					if err != nil {
						panic(vm.MakeCustomError("TemplateTokenToObject", err.Error()))
					}
					s, err := val.ToString()
					if err != nil {
						panic(vm.MakeCustomError("TemplateTokenToObject", err.Error()))
					}
					var token protocol.TemplateToken
					err = json.Unmarshal([]byte(s), &token)
					if err != nil {
						panic(vm.MakeCustomError("TemplateTokenToObject", err.Error()))
					}
					return token.ToJSONRawObject()
				})
				contextData := make(map[string]interface{})
				if jobreq.ContextData != nil {
					for k, ctxdata := range jobreq.ContextData {
						contextData[k] = ctxdata.ToRawObject()
					}
				}
				vm.Set("contextData", contextData)
				val, err := vm.Run(instance.RunnerGuard)
				if err != nil {
					fmt.Printf("Failed to run `%v`: %v", instance.RunnerGuard, err)
					finishJob("Failed")
					return
				}
				res, _ := val.ToBoolean()
				if !res {
					finishJob("Failed")
					return
				}
			}
		}
		wrap := &protocol.TimelineRecordWrapper{}
		wrap.Count = 2
		wrap.Value = make([]protocol.TimelineRecord, wrap.Count)
		wrap.Value[0] = protocol.CreateTimelineEntry("", rqt.JobName, rqt.JobDisplayName)
		wrap.Value[0].ID = rqt.JobID
		wrap.Value[0].Type = "Job"
		wrap.Value[0].Order = 0
		wrap.Value[0].Start()
		wrap.Value[1] = protocol.CreateTimelineEntry(rqt.JobID, "__setup", "Setup Job")
		wrap.Value[1].Order = 1
		wrap.Value[1].Start()
		vssConnection.UpdateTimeLine(jobreq.Timeline.ID, jobreq, wrap)
		failInitJob2 := func(title string, message string) {
			wrap.Value = append(wrap.Value, protocol.CreateTimelineEntry(rqt.JobID, "__fatal_error", title))
			id, _ := vssConnection.UploadLogFile(jobreq.Timeline.ID, jobreq, message)
			wrap.Value[wrap.Count].Log = &protocol.TaskLogReference{ID: id}
			wrap.Value[wrap.Count].Start()
			wrap.Value[wrap.Count].Complete("Failed")
			wrap.Value[wrap.Count].Order = int32(wrap.Count)
			wrap.Count++
			wrap.Value[0].Complete("Failed")
			vssConnection.UpdateTimeLine(jobreq.Timeline.ID, jobreq, wrap)
			fmt.Println(message)
			finishJob("Failed")
		}
		failInitJob := func(message string) {
			failInitJob2("Failed to initialize Job", message)
		}
		defer func() {
			if err := recover(); err != nil {
				failInitJob2("Worker panicked", "The worker panicked with message: "+fmt.Sprint(err)+"\n"+string(debug.Stack()))
			}
		}()
		jobVssConnection, vssConnectionData, err := jobreq.GetConnection("SystemVssConnection")
		if err != nil {
			failInitJob(err.Error())
			return
		}
		jobVssConnection.Client = vssConnection.Client
		jobVssConnection.Trace = vssConnection.Trace
		vssConnection = jobVssConnection
		rawGithubCtx, ok := rqt.ContextData["github"]
		if !ok {
			fmt.Println("missing github context in ContextData")
			finishJob("Failed")
			return
		}
		githubCtx := rawGithubCtx.ToRawObject()
		matrix, err := actionsdotnetactcompat.ConvertMatrixInstance(rqt.ContextData)
		if err != nil {
			failInitJob(err.Error())
		}
		env, err := actionsdotnetactcompat.ConvertEnvironment(rqt.EnvironmentVariables)
		if err != nil {
			failInitJob(err.Error())
		}
		env["ACTIONS_RUNTIME_URL"] = vssConnection.TenantURL
		env["ACTIONS_RUNTIME_TOKEN"] = vssConnection.Token

		if cacheUrl, ok := vssConnectionData["CacheServerUrl"]; ok && len(cacheUrl) > 0 {
			env["ACTIONS_CACHE_URL"] = cacheUrl
		}
		if idTokenUrl, ok := vssConnectionData["GenerateIdTokenUrl"]; ok && len(idTokenUrl) > 0 {
			env["ACTIONS_ID_TOKEN_REQUEST_URL"] = idTokenUrl
			env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = vssConnection.Token
		}

		defaults, err := actionsdotnetactcompat.ConvertDefaults(rqt.Defaults)
		if err != nil {
			failInitJob(err.Error())
		}
		steps, err := actionsdotnetactcompat.ConvertSteps(rqt.Steps)
		if err != nil {
			failInitJob(err.Error())
		}
		actions_step_debug := false
		if sd, ok := rqt.Variables["ACTIONS_STEP_DEBUG"]; ok && (sd.Value == "true" || sd.Value == "1") {
			actions_step_debug = true
		}
		rawContainer := yaml.Node{}
		if rqt.JobContainer != nil {
			rawContainer = *rqt.JobContainer.ToYamlNode()
			if actions_step_debug {
				// Fake step to catch the post debug log
				steps = append(steps, &model.Step{
					ID:               "___finish_job",
					If:               yaml.Node{Kind: yaml.ScalarNode, Value: "false"},
					Name:             "Finish Job",
					Run:              "",
					Env:              yaml.Node{},
					ContinueOnError:  true,
					WorkingDirectory: "",
					Shell:            "",
				})
			}
		}
		services, err := actionsdotnetactcompat.ConvertServiceContainer(rqt.JobServiceContainers)
		githubCtxMap, ok := githubCtx.(map[string]interface{})
		if !ok {
			failInitJob("Github ctx is not a map")
			return
		}
		var payload string
		{
			e, _ := json.Marshal(githubCtxMap["event"])
			payload = string(e)
		}
		// Non customizable config
		runnerConfig.Workdir = "./"
		if runtime.GOOS == "windows" {
			runnerConfig.Workdir = ".\\"
		}
		runnerConfig.Platforms = map[string]string{
			"dummy": "-self-hosted",
		}
		runnerConfig.LogOutput = true
		runnerConfig.EventName = githubCtxMap["event_name"].(string)
		runnerConfig.GitHubServerUrl = githubCtxMap["server_url"].(string)
		runnerConfig.GitHubApiServerUrl = githubCtxMap["api_url"].(string)
		runnerConfig.GitHubGraphQlApiServerUrl = githubCtxMap["graphql_url"].(string)
		runnerConfig.ForceRemoteCheckout = true // Needed to avoid copy the non exiting working dir
		runnerConfig.AutoRemove = true          // Needed to cleanup always cleanup container
		rc := &runner.RunContext{
			Name:   uuid.New().String(),
			Config: runnerConfig,
			Env:    env,
			Run: &model.Run{
				JobID: rqt.JobID,
				Workflow: &model.Workflow{
					Name:     githubCtxMap["workflow"].(string),
					Defaults: defaults,
					Jobs: map[string]*model.Job{
						rqt.JobID: {
							If:           yaml.Node{Value: "always()"},
							Name:         rqt.JobDisplayName,
							RawRunsOn:    yaml.Node{Kind: yaml.ScalarNode, Value: "dummy"},
							Steps:        steps,
							RawContainer: rawContainer,
							Services:     services,
							Outputs:      make(map[string]string),
						},
					},
				},
			},
			Matrix:    matrix,
			EventJSON: payload,
		}

		// Prepare act to provide inputs for workflow_call
		if rawInputsCtx, ok := rqt.ContextData["inputs"]; ok {
			rawInputs := rawInputsCtx.ToRawObject()
			if rawInputsMap, ok := rawInputs.(map[string]interface{}); ok {
				rc.Inputs = rawInputsMap
			}
		}
		// Prepare act to fill previous job outputs
		if rawNeedstx, ok := rqt.ContextData["needs"]; ok {
			needsCtx := rawNeedstx.ToRawObject()
			if needsCtxMap, ok := needsCtx.(map[string]interface{}); ok {
				a := make([]*yaml.Node, 0)
				for k, v := range needsCtxMap {
					a = append(a, &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: k})
					outputs := make(map[string]string)
					result := "success"
					if jobMap, ok := v.(map[string]interface{}); ok {
						if jobOutputs, ok := jobMap["outputs"]; ok {
							if outputMap, ok := jobOutputs.(map[string]interface{}); ok {
								for k, v := range outputMap {
									if sv, ok := v.(string); ok {
										outputs[k] = sv
									}
								}
							}
						}
						if res, ok := jobMap["result"]; ok {
							if resstr, ok := res.(string); ok {
								result = resstr
							}
						}
					}
					rc.Run.Workflow.Jobs[k] = &model.Job{
						Outputs: outputs,
						Result:  result,
					}
				}
				rc.Run.Workflow.Jobs[rqt.JobID].RawNeeds = yaml.Node{Kind: yaml.SequenceNode, Content: a}
			}
		}
		// Prepare act to add job outputs to current job
		if rqt.JobOutputs != nil {
			o := rqt.JobOutputs.ToRawObject()
			if m, ok := o.(map[interface{}]interface{}); ok {
				for k, v := range m {
					if kv, ok := k.(string); ok {
						if sv, ok := v.(string); ok {
							rc.Run.Workflow.Jobs[rqt.JobID].Outputs[kv] = sv
						}
					}
				}
			}
		}

		if name, ok := rqt.Variables["system.github.job"]; ok {
			rc.JobName = name.Value
			// Add the job name to the overlay, otherwise this property is empty
			if githubCtxMap != nil {
				githubCtxMap["job"] = name.Value
			}
		}
		val, _ := json.Marshal(githubCtx)
		sv := string(val)
		rc.GithubContextBase = &sv

		ee := rc.NewExpressionEvaluator()
		rc.ExprEval = ee
		logger := logrus.New()

		formatter := new(ghaFormatter)
		formatter.rc = rc
		formatter.rqt = rqt
		formatter.stepBuffer = &bytes.Buffer{}

		logger.SetFormatter(formatter)
		logger.SetOutput(io.MultiWriter())
		if actions_step_debug {
			logger.SetLevel(logrus.DebugLevel)
		} else {
			logger.SetLevel(logrus.InfoLevel)
		}

		rc.CurrentStep = "__setup"
		rc.StepResults = make(map[string]*model.StepResult)
		rc.StepResults[rc.CurrentStep] = &model.StepResult{}

		for i := 0; i < len(steps); i++ {
			wrap.Value = append(wrap.Value, protocol.CreateTimelineEntry(rqt.JobID, steps[i].ID, steps[i].String()))
			wrap.Value[i+2].Order = int32(i + 2)
		}
		formatter.current = &wrap.Value[1]
		wrap.Count = int64(len(wrap.Value))
		vssConnection.UpdateTimeLine(jobreq.Timeline.ID, jobreq, wrap)
		{
			formatter.updateTimeLine = func() {
				vssConnection.UpdateTimeLine(jobreq.Timeline.ID, jobreq, wrap)
			}
			formatter.uploadLogFile = func(log string) int {
				id, _ := vssConnection.UploadLogFile(jobreq.Timeline.ID, jobreq, log)
				return id
			}
		}
		var outputMap *map[string]protocol.VariableValue
		jobStatus := "success"
		cancelled := false
		{
			runCtx, cancelRun := context.WithCancel(context.Background())
			logctx, cancelLog := context.WithCancel(context.Background())
			defer func() {
				cancelRun()
				<-logctx.Done()
			}()
			{
				logchan := make(chan *protocol.TimelineRecordFeedLinesWrapper, 64)
				formatter.logline = func(startLine int64, recordId string, lines []string) {
					wrapper := &protocol.TimelineRecordFeedLinesWrapper{}
					wrapper.Value = lines
					wrapper.Count = int64(len(lines))
					wrapper.StartLine = &startLine
					wrapper.StepID = recordId
					logchan <- wrapper
				}
				go func() {
					defer cancelLog()
					sendLogSlow := func(lines *protocol.TimelineRecordFeedLinesWrapper) {
						vssConnection.SendLogLines(jobreq.Plan, jobreq.Timeline.ID, lines)
						if err != nil {
							fmt.Println("Failed to upload logline: " + err.Error())
						}
					}
					sendLog := sendLogSlow
					if rawFeedStreamUrl, ok := vssConnectionData["FeedStreamUrl"]; ok {
						re := regexp.MustCompile("(?i)^http(s?)://")
						feedStreamUrl, _ := url.Parse(re.ReplaceAllString(rawFeedStreamUrl, "ws$1://"))
						origin, _ := url.Parse(vssConnection.TenantURL)
						wsMessagesSent := 0
						dialSocket := func() (ws *websocket.Conn, err error) {
							wsMessagesSent = 0
							return websocket.DialConfig(&websocket.Config{
								Location: feedStreamUrl,
								Origin:   origin,
								Version:  13,
								Header: http.Header{
									"Authorization": []string{"Bearer " + vssConnection.Token},
								},
							})
						}
						ws, err := dialSocket()
						if err == nil {
							sendLog = func(lines *protocol.TimelineRecordFeedLinesWrapper) {
								err := websocket.JSON.Send(ws, lines)
								if err == nil {
									wsMessagesSent++
								} else if wsMessagesSent > 0 {
									ws, err = dialSocket()
									if err == nil {
										sendLog(lines)
									} else {
										sendLog = sendLogSlow
									}
								} else {
									sendLog = sendLogSlow
								}
							}
							defer func() {
								ws.Close()
							}()
						}
					}
					for {
						select {
						case <-runCtx.Done():
							return
						case lines := <-logchan:
							st := time.Now()
							lp := st
							logsexit := false
							for {
								b := false
								div := lp.Sub(st)
								if div > time.Second {
									break
								}
								select {
								case line := <-logchan:
									if line.StepID == lines.StepID {
										lines.Count += line.Count
										lines.Value = append(lines.Value, line.Value...)
									} else {
										sendLog(lines)
										lines = line
										st = time.Now()
									}
								case <-time.After(time.Second - div):
									b = true
								case <-runCtx.Done():
									b = true
									logsexit = true
								}
								if b {
									break
								}
								lp = time.Now()
							}
							sendLog(lines)
							if logsexit {
								return
							}
						}
					}
				}()
			}
			formatter.wrap = wrap

			logger.Log(logrus.InfoLevel, "Runner Name: "+instance.Agent.Name)
			logger.Log(logrus.InfoLevel, "Runner OSDescription: github-act-runner "+runtime.GOOS+"/"+runtime.GOARCH)
			logger.Log(logrus.InfoLevel, "Runner Version: "+version)

			// Wait for possible concurrent running job and serialize, this only happens for multi repository runners
			waitContext, finishWait := context.WithCancel(jobExecCtx)
			defer finishWait()
			go func() {
				for {
					select {
					case <-waitContext.Done():
						return
					case <-time.After(5 * time.Second):
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
			var err error
			select {
			case <-joblch:
				finishWait()
				// The following code is synchronized
				logrus.SetLevel(logger.GetLevel())
				logrus.SetFormatter(formatter)
				logrus.SetOutput(io.MultiWriter())

				cacheDir := rc.ActionCacheDir()
				if err := os.MkdirAll(cacheDir, 0777); err != nil {
					logger.Warn("github-act-runner is be unable to access \"" + cacheDir + "\". You might want set one of the following environment variables XDG_CACHE_HOME, HOME to a user read and writeable location. Details: " + err.Error())
				}
				err = rc.Executor()(common.WithJobErrorContainer(common.WithLogger(jobExecCtx, logger)))
			case <-jobExecCtx.Done():
			}

			if err != nil {
				logger.Logf(logrus.ErrorLevel, "%v", err.Error())
				jobStatus = "failure"
			}
			// Prepare results for github server
			if rqt.JobOutputs != nil {
				m := make(map[string]protocol.VariableValue)
				outputMap = &m
				for k, v := range rc.Run.Workflow.Jobs[rqt.JobID].Outputs {
					m[k] = protocol.VariableValue{Value: v}
				}
			}

			for _, stepStatus := range rc.StepResults {
				if stepStatus.Conclusion == model.StepStatusFailure {
					jobStatus = "failure"
					break
				}
			}
			select {
			case <-jobExecCtx.Done():
				cancelled = true
			default:
			}
			{
				f := formatter
				f.startLine = 1
				if f.current != nil {
					if f.current == &wrap.Value[1] {
						// Workaround check for init failure, e.g. docker fails
						if cancelled {
							f.current.Complete("Canceled")
						} else {
							jobStatus = "failure"
							f.current.Complete("Failed")
						}
					} else if f.rc.StepResults[f.current.RefName].Conclusion == model.StepStatusSuccess {
						f.current.Complete("Succeeded")
					} else if f.rc.StepResults[f.current.RefName].Conclusion == model.StepStatusSkipped {
						f.current.Complete("Skipped")
					} else {
						f.current.Complete("Failed")
					}
					if f.stepBuffer.Len() > 0 {
						f.current.Log = &protocol.TaskLogReference{ID: f.uploadLogFile(f.stepBuffer.String())}
					}
				}
			}
			for i := 2; i < len(wrap.Value); i++ {
				if !strings.EqualFold(wrap.Value[i].State, "Completed") {
					wrap.Value[i].Complete("Skipped")
				}
			}
			if cancelled {
				wrap.Value[0].Complete("Canceled")
			} else if jobStatus == "success" {
				wrap.Value[0].Complete("Succeeded")
			} else {
				wrap.Value[0].Complete("Failed")
			}
		}
		for i := 0; ; i++ {
			if vssConnection.UpdateTimeLine(jobreq.Timeline.ID, jobreq, wrap) != nil && i < 10 {
				fmt.Printf("Retry uploading the final timeline of the job in 10 seconds attempt %v of 10\n", i+1)
				<-time.After(time.Second * 10)
			} else {
				break
			}
		}
		result := "Failed"
		if cancelled {
			result = "Canceled"
		} else if jobStatus == "success" {
			result = "Succeeded"
		}
		finishJob2(result, outputMap)
	}()
}

var version string = "0.3.x-dev"

type interactive struct {
}

func (i *interactive) GetInput(prompt string, def string) string {
	return GetInput(prompt, def)
}
func (i *interactive) GetSelectInput(prompt string, options []string, def string) string {
	return RunnerGroupSurvey(def, options)
}
func (i *interactive) GetMultiSelectInput(prompt string, options []string) []string {
	return GetMultiSelectInput(prompt, options)
}

func main() {
	config := &runnerconfiguration.ConfigureRunner{}
	run := &RunRunner{}
	remove := &runnerconfiguration.RemoveRunner{}
	var cmdConfigure = &cobra.Command{
		Use:   "configure",
		Short: "Configure your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if len(config.Pat) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_PAT"); ok {
					config.Pat = v
				}
			}
			if len(config.Token) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_TOKEN"); ok {
					config.Token = v
				}
			}
			if !config.Unattended {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_UNATTENDED"); ok {
					config.Unattended = strings.EqualFold(v, "true") || strings.EqualFold(v, "Y")
				}
			}
			if !config.Ephemeral {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_EPHEMERAL"); ok {
					config.Ephemeral = strings.EqualFold(v, "true") || strings.EqualFold(v, "Y")
				}
			}
			if len(config.Name) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_NAME"); ok {
					config.Name = v
				}
			}
			if len(config.URL) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_URL"); ok {
					config.URL = v
				}
			}
			if len(config.Labels) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_LABELS"); ok {
					config.Labels = strings.Split(v, ",")
				}
			}
			if !config.Replace {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_REPLACE"); ok {
					config.Replace = strings.EqualFold(v, "true") || strings.EqualFold(v, "Y")
				}
			}
			settings, _ := loadConfiguration()
			settings, err := config.Configure(settings, &interactive{}, nil)
			if settings != nil {
				os.Remove("agent.json")
				os.Remove("auth.json")
				os.Remove("cred.pkcs1")
				WriteJson("settings.json", settings)
			}
			if err != nil {
				fmt.Printf("failed to configure: %v", err)
				os.Exit(1)
			} else {
				fmt.Printf("success")
				os.Exit(0)
			}
		},
	}

	cmdConfigure.Flags().StringVar(&config.URL, "url", "", "url of your repository, organization or enterprise")
	cmdConfigure.Flags().StringVar(&config.Token, "token", "", "runner registration token")
	cmdConfigure.Flags().StringVar(&config.Pat, "pat", "", "personal access token with access to your repository, organization or enterprise")
	cmdConfigure.Flags().StringSliceVarP(&config.Labels, "labels", "l", []string{}, "custom user labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Name, "name", "", "custom runner name")
	cmdConfigure.Flags().BoolVar(&config.NoDefaultLabels, "no-default-labels", false, "do not automatically add the following system labels: self-hosted, "+runtime.GOOS+" and "+runtime.GOARCH)
	cmdConfigure.Flags().StringSliceVarP(&config.SystemLabels, "system-labels", "", []string{}, "custom system labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Token, "runnergroup", "", "name of the runner group to use will ask if more than one is available")
	cmdConfigure.Flags().BoolVar(&config.Unattended, "unattended", false, "suppress shell prompts during configure")
	cmdConfigure.Flags().BoolVar(&config.Trace, "trace", false, "trace http communication with the github action service")
	cmdConfigure.Flags().BoolVar(&config.Ephemeral, "ephemeral", false, "configure a single use runner, runner deletes it's setting.json ( and the actions service should remove their registrations at the same time ) after executing one job ( implies '--once' on run ). This is not supported for multi runners.")
	cmdConfigure.Flags().StringVar(&config.RunnerGuard, "runner-guard", "", "reject jobs and configure act")
	cmdConfigure.Flags().BoolVar(&config.Replace, "replace", false, "replace any existing runner with the same name")
	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "run your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(run.Run())
		},
	}

	cmdRun.Flags().BoolVar(&run.Once, "once", false, "only execute one job and exit")
	cmdRun.Flags().BoolVarP(&run.Terminal, "terminal", "t", true, "allocate a pty if possible")
	cmdRun.Flags().BoolVar(&run.Trace, "trace", false, "trace http communication with the github action service")
	var cmdRemove = &cobra.Command{
		Use:   "remove",
		Short: "remove your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if len(remove.Pat) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_PAT"); ok {
					remove.Pat = v
				}
			}
			if len(remove.Token) == 0 {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_TOKEN"); ok {
					remove.Token = v
				}
			}
			if !remove.Unattended {
				if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_UNATTENDED"); ok {
					remove.Unattended = strings.EqualFold(v, "true") || strings.EqualFold(v, "Y")
				}
			}
			settings, err := loadConfiguration()
			if err != nil {
				fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
				os.Exit(1)
			}
			settings, err = remove.Remove(settings, &interactive{}, nil)
			if settings != nil {
				os.Remove("agent.json")
				os.Remove("auth.json")
				os.Remove("cred.pkcs1")
				WriteJson("settings.json", settings)
			}
			if err != nil {
				fmt.Printf("failed to remove: %v", err)
				os.Exit(1)
			} else {
				fmt.Printf("success")
				os.Exit(0)
			}
		},
	}

	cmdRemove.Flags().StringVar(&remove.URL, "url", "", "url of your repository, organization or enterprise ( required to unconfigure version <= 0.0.3 )")
	cmdRemove.Flags().StringVar(&remove.Token, "token", "", "runner registration or remove token")
	cmdRemove.Flags().StringVar(&remove.Pat, "pat", "", "personal access token with access to your repository, organization or enterprise")
	cmdRemove.Flags().BoolVar(&remove.Unattended, "unattended", false, "suppress shell prompts during configure")
	cmdRemove.Flags().StringVar(&remove.Name, "name", "", "name of the runner to remove")
	cmdRemove.Flags().BoolVar(&remove.Trace, "trace", false, "trace http communication with the github action service")
	cmdRemove.Flags().BoolVar(&remove.Force, "force", false, "force remove the instance even if the service responds with an error")

	var rootCmd = &cobra.Command{
		Use:     "github-act-runner",
		Version: version,
	}
	rootCmd.AddCommand(cmdConfigure, cmdRun, cmdRemove)
	rootCmd.Execute()
}
