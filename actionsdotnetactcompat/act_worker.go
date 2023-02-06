package actionsdotnetactcompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/google/uuid"
	"github.com/nektos/act/pkg/common"
	"github.com/nektos/act/pkg/model"
	"github.com/nektos/act/pkg/runner"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type ghaFormatter struct {
	rqt           *protocol.AgentJobRequestMessage
	rc            *runner.RunContext
	logger        *protocol.JobLogger
	linefeedregex *regexp.Regexp
}

func flushInternal(rec *protocol.TimelineRecord, res *model.StepResult) {
	if res.Conclusion == model.StepStatusSuccess {
		rec.Complete("Succeeded")
	} else if res.Conclusion == model.StepStatusSkipped {
		rec.Complete("Skipped")
	} else {
		rec.Complete("Failed")
	}
}

func (f *ghaFormatter) Flush() {
	cur := f.logger.Current()
	if cur == nil {
		return
	}
	if res, ok := f.rc.StepResults[cur.RefName]; ok {
		flushInternal(cur, res)
	}
	for {
		next := f.logger.MoveNext()
		if next == nil {
			break
		}
		next.Complete("Skipped")
	}
}

func (f *ghaFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	if cur := f.logger.Current(); f.rc != nil && f.rc.Parent == nil && cur != nil && cur.RefName != f.rc.CurrentStep {
		if res, ok := f.rc.StepResults[cur.RefName]; ok {
			flushInternal(cur, res)
			for {
				next := f.logger.MoveNext()
				if next == nil || next.RefName == f.rc.CurrentStep {
					break
				}
				next.Complete("Skipped")
			}
			if cur := f.logger.Current(); cur != nil {
				cur.Start()
			}
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
			if v.IsSecret && len(v.Value) > 0 && !strings.EqualFold(v.Value, "true") && !strings.EqualFold(v.Value, "false") && !strings.EqualFold(v.Value, "0") && !strings.EqualFold(v.Value, "1") {
				entry.Message = strings.ReplaceAll(entry.Message, v.Value, "***")
			}
		}
	}

	if f.linefeedregex == nil {
		f.linefeedregex = regexp.MustCompile(`(\r\n|\r|\n)`)
	}

	prefix := entry.Time.UTC().Format("2006-01-02T15:04:05.0000000Z ")
	if entry.Level == logrus.DebugLevel {
		prefix += "##[debug]"
	} else if entry.Level == logrus.WarnLevel {
		prefix += "##[warning]"
	} else if entry.Level == logrus.ErrorLevel {
		prefix += "##[error]"
	}
	entry.Message = f.linefeedregex.ReplaceAllString(prefix+strings.Trim(entry.Message, "\r\n"), "\n"+prefix)

	b.WriteString(entry.Message)
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func ExecWorker(rqt *protocol.AgentJobRequestMessage, jlogger *protocol.JobLogger, jobExecCtx context.Context) {
	logger := logrus.New()
	logger.SetOutput(jlogger)
	formatter := &ghaFormatter{
		rqt:    rqt,
		logger: jlogger,
	}
	logger.SetFormatter(formatter)
	logger.Println("Initialize translating the job request to nektos/act")
	vssConnection, vssConnectionData, _ := rqt.GetConnection("SystemVssConnection")
	finishJob2 := func(result string, outputs *map[string]protocol.VariableValue) {
		jlogger.TimelineRecords.Value[0].Complete(result)
		jlogger.Logger.Close()
		jlogger.Finish()
		finish := &protocol.JobEvent{
			Name:      "JobCompleted",
			JobID:     rqt.JobID,
			RequestID: rqt.RequestID,
			Result:    result,
			Outputs:   outputs,
		}
		vssConnection.FinishJob(finish, rqt.Plan)
	}
	finishJob := func(result string) {
		finishJob2(result, &map[string]protocol.VariableValue{})
	}
	failInitJob2 := func(title string, message string) {
		e := jlogger.Append(protocol.CreateTimelineEntry(rqt.JobID, "__fatal", title))
		e.Start()
		jlogger.Log(message)
		e.Complete("Failed")
		finishJob("Failed")
	}
	failInitJob := func(message string) {
		failInitJob2("Failed to initialize Job", message)
	}
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
	rawGithubCtx, ok := rqt.ContextData["github"]
	if !ok {
		fmt.Println("missing github context in ContextData")
		finishJob("Failed")
		return
	}
	githubCtx := rawGithubCtx.ToRawObject()
	matrix, err := ConvertMatrixInstance(rqt.ContextData)
	if err != nil {
		failInitJob(err.Error())
	}
	env, err := ConvertEnvironment(rqt.EnvironmentVariables)
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

	defaults, err := ConvertDefaults(rqt.Defaults)
	if err != nil {
		failInitJob(err.Error())
	}
	steps, err := ConvertSteps(rqt.Steps)
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
	services, err := ConvertServiceContainer(rqt.JobServiceContainers)
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
		Matrix:      matrix,
		EventJSON:   payload,
		ContextData: map[string]interface{}{},
	}
	for k, v := range rqt.ContextData {
		rc.ContextData[k] = v.ToRawObject()
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

	formatter.rc = rc
	if actions_step_debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	rc.CurrentStep = jlogger.Current().RefName
	rc.StepResults = make(map[string]*model.StepResult)
	rc.StepResults[rc.CurrentStep] = &model.StepResult{}

	for i := 0; i < len(steps); i++ {
		jlogger.Append(protocol.CreateTimelineEntry(rqt.JobID, steps[i].ID, steps[i].String()))
	}

	logrus.SetLevel(logger.GetLevel())
	logrus.SetFormatter(logger.Formatter)
	logrus.SetOutput(logger.Out)

	cacheDir := rc.ActionCacheDir()
	if err := os.MkdirAll(cacheDir, 0777); err != nil {
		logger.Warn("github-act-runner is be unable to access \"" + cacheDir + "\". You might want set one of the following environment variables XDG_CACHE_HOME, HOME to a user read and writeable location. Details: " + err.Error())
	}
	logger.Println("Starting nektos/act")
	select {
	case <-jobExecCtx.Done():
	default:
		ctxError := common.WithJobErrorContainer(common.WithLogger(jobExecCtx, logger))
		err = rc.Executor()(ctxError)
		if err == nil {
			err = common.JobError(ctxError)
		}
	}

	jobStatus := "Succeeded"
	var outputMap *map[string]protocol.VariableValue

	if err != nil {
		logger.Logf(logrus.ErrorLevel, "%v", err.Error())
		jobStatus = "Failed"
	}
	formatter.Flush()

	// Prepare results for github server
	if rqt.JobOutputs != nil {
		m := make(map[string]protocol.VariableValue)
		outputMap = &m
		for k, v := range rc.Run.Workflow.Jobs[rqt.JobID].Outputs {
			m[k] = protocol.VariableValue{Value: v}
		}
	}

	select {
	case <-jobExecCtx.Done():
		jobStatus = "Canceled"
	default:
	}
	finishJob2(jobStatus, outputMap)
}
