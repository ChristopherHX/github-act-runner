package actionsdotnetactcompat

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/actionsrunner"
	rcommon "github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/launch"
	"github.com/ChristopherHX/github-act-runner/protocol/logger"
	"github.com/google/uuid"
	"github.com/nektos/act/pkg/common"
	"github.com/nektos/act/pkg/common/git"
	"github.com/nektos/act/pkg/container"
	"github.com/nektos/act/pkg/model"
	"github.com/nektos/act/pkg/runner"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type ghaFormatter struct {
	rqt           *protocol.AgentJobRequestMessage
	rc            *runner.RunContext
	logger        *logger.JobLogger
	linefeedregex *regexp.Regexp
	main          bool
	result        *model.StepResult
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
	if f.result != nil {
		flushInternal(cur, f.result)
	} else if cur.Result == nil {
		// If act fails during init e.g to docker is not running
		cur.Complete("Failed")
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
	var stepID string
	stage, hasStage := entry.Data["stage"]
	rawStepID, hasStepID := entry.Data["stepID"]

	if stepResult, hasStepResult := entry.Data["stepResult"]; hasStepResult {
		res := stepResult
		switch res {
		case model.StepStatusSuccess:
			f.result = &model.StepResult{Conclusion: model.StepStatusSuccess}
		case model.StepStatusFailure:
			f.result = &model.StepResult{Conclusion: model.StepStatusFailure}
		case model.StepStatusSkipped:
			f.result = &model.StepResult{Conclusion: model.StepStatusSkipped}
		}
	}
	if hasStepID {
		stepIDArray, _ := rawStepID.([]string)
		var prefix string
		if hasStage && stage != "Main" {
			prefix = stage.(string) + "-"
		}
		stepID = prefix + stepIDArray[0]
	}
	cur := f.logger.Current()
	if !f.main && hasStepID {
		f.main = true
		flushInternal(cur, &model.StepResult{Conclusion: model.StepStatusSuccess})
	}
	stepName, hasStepName := entry.Data["step"]
	if hasStepName && hasStepID && f.logger.Current().RefName != stepID {
		if stage == "Post" {
			f.Flush()
		} else if f.result != nil {
			flushInternal(cur, f.result)
		}
		f.result = &model.StepResult{Conclusion: model.StepStatusSuccess}
		if stage != "Main" {
			// skip starting the first main step record
			f.logger.MoveNextExt(false)
			te := protocol.CreateTimelineEntry(f.logger.TimelineRecords.Value[0].ID, stepID, stage.(string)+" "+stepName.(string))
			te.Order = f.logger.TimelineRecords.Value[f.logger.CurrentRecord-1].Order + 1
			f.logger.Insert(te)
			f.logger.Current().Start()
			f.logger.Update()
		} else {
			for {
				next := f.logger.MoveNext()
				if next == nil || next.RefName == stepID {
					break
				}
				next.Complete("Skipped")
			}
			if cur := f.logger.Current(); cur != nil {
				cur.Start()
			}
			f.logger.Update()
		}
	}
	//js, _ := json.Marshal(entry.Data)
	//entry.Message = (string)(js) + "|" + entry.Message

	// if f.rc != nil && f.rc.Parent == nil && (f.logger.Current() == nil || f.logger.Current().RefName != f.rc.CurrentStep) {
	// 	if res, ok := f.rc.StepResults[f.logger.Current().RefName]; ok && f.logger.Current() != nil {
	// 		f.flushInternal(res)
	// 		for {
	// 			next := f.logger.MoveNext()
	// 			if next == nil || next.RefName == f.rc.CurrentStep {
	// 				break
	// 			}
	// 			f.logger.Current().Complete("Skipped")
	// 		}
	// 		f.logger.Current().Start()
	// 	}
	// }
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

	prefix := entry.Time.UTC().Format(protocol.TimestampOutputFormat) + " "
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

type JobLoggerFactory struct {
	Logger *logrus.Logger
}

func (factory *JobLoggerFactory) WithJobLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(factory.Logger.Out)
	logger.SetLevel(factory.Logger.Level)
	logger.SetFormatter(factory.Logger.Formatter)
	return logger
}

func ExecWorker(rqt *protocol.AgentJobRequestMessage, wc actionsrunner.WorkerContext) {
	jlogger := wc.Logger()
	jobExecCtx := wc.JobExecCtx()
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
		wc.FinishJob(result, outputs)
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
	runnerConfig := &runner.Config{
		Secrets: secrets,
	}
	if rqt.Variables != nil {
		for k, v := range rqt.Variables {
			if v.IsSecret && k != "system.github.token" {
				secrets[k] = v.Value
			}
		}
		if rawGithubToken, ok := rqt.Variables["system.github.token"]; ok {
			secrets["GITHUB_TOKEN"] = rawGithubToken.Value
			runnerConfig.Token = rawGithubToken.Value
		}
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
	runnerConfig.GitHubInstance = "github.com"
	runnerConfig.GitHubServerUrl = githubCtxMap["server_url"].(string)
	runnerConfig.GitHubApiServerUrl = githubCtxMap["api_url"].(string)
	runnerConfig.GitHubGraphQlApiServerUrl = githubCtxMap["graphql_url"].(string)
	runnerConfig.NoSkipCheckout = true // Needed to avoid copy the non exiting working dir
	runnerConfig.AutoRemove = true     // Needed to cleanup always cleanup container
	runnerConfig.ForcePull = true
	runnerConfig.ForceRebuild = true
	runnerConfig.DownloadAction = func(ngcei git.NewGitCloneExecutorInput) common.Executor {
		return func(ctx context.Context) error {
			actionList := &protocol.ActionReferenceList{}
			actionurl := strings.Split(ngcei.URL, "/")
			actionurl = actionurl[len(actionurl)-2:]
			actionList.Actions = []protocol.ActionReference{
				{NameWithOwner: strings.Join(actionurl, "/"), Ref: ngcei.Ref},
			}
			actionDownloadInfo := &protocol.ActionDownloadInfoCollection{}
			err := vssConnection.RequestWithContext(ctx, "27d7f831-88c1-4719-8ca1-6a061dad90eb", "6.0-preview", "POST", map[string]string{
				"scopeIdentifier": rqt.Plan.ScopeIdentifier,
				"hubName":         rqt.Plan.PlanType,
				"planId":          rqt.Plan.PlanID,
			}, nil, actionList, actionDownloadInfo)
			if err != nil {
				return err
			}
			for _, v := range actionDownloadInfo.Actions {
				token := runnerConfig.Token
				if v.Authentication != nil && v.Authentication.Token != "" {
					token = v.Authentication.Token
				}
				err := downloadAndExtractAction(ctx, ngcei.Dir, actionurl[0], actionurl[1], v.ResolvedSha, v.TarballUrl, token, vssConnection.Client)
				if err != nil {
					return err
				}
			}
			return nil
		}
	}
	if strings.EqualFold(rqt.MessageType, "RunnerJobRequest") {
		runnerConfig.DownloadAction = nil
		launchEndpoint, hasLaunchEndpoint := rqt.Variables["system.github.launch_endpoint"]
		if hasLaunchEndpoint && launchEndpoint.Value != "" {
			runnerConfig.DownloadAction = func(ngcei git.NewGitCloneExecutorInput) common.Executor {
				return func(ctx context.Context) error {
					actionList := &launch.ActionReferenceRequestList{}
					actionurl := strings.Split(ngcei.URL, "/")
					actionurl = actionurl[len(actionurl)-2:]
					actionList.Actions = []launch.ActionReferenceRequest{
						{Action: strings.Join(actionurl, "/"), Version: ngcei.Ref},
					}
					actionDownloadInfo := &launch.ActionDownloadInfoResponseCollection{}
					urlBuilder := protocol.VssConnection{TenantURL: launchEndpoint.Value}
					url, err := urlBuilder.BuildURL("actions/build/{planId}/jobs/{jobId}/runnerresolve/actions", map[string]string{
						"jobId":  rqt.JobID,
						"planId": rqt.Plan.PlanID,
					}, nil)
					if err != nil {
						return err
					}
					err = vssConnection.RequestWithContext2(ctx, "POST", url, "", actionList, actionDownloadInfo)
					if err != nil {
						return err
					}
					for _, v := range actionDownloadInfo.Actions {
						token := runnerConfig.Token
						if v.Authentication != nil && v.Authentication.Token != "" {
							token = v.Authentication.Token
						}
						err := downloadAndExtractAction(ctx, ngcei.Dir, actionurl[0], actionurl[1], v.ResolvedSha, v.TarUrl, token, vssConnection.Client)
						if err != nil {
							return err
						}
					}
					return nil
				}
			}
		}
	}
	if viaGit, hasViaGit := rcommon.LookupEnvBool("GITHUB_ACT_RUNNER_DOWNLOAD_ACTIONS_VIA_GIT"); hasViaGit && viaGit {
		runnerConfig.DownloadAction = nil
	}
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

	rc.ContextData = make(map[string]interface{})
	// Prepare act to provide inputs for workflow_call
	for k, rawInputsCtx := range rqt.ContextData {
		rc.ContextData[k] = rawInputsCtx.ToRawObject()
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
	rc.ContextData["github"] = githubCtxMap
	val, _ := json.Marshal(githubCtx)
	sv := string(val)
	rc.GHContextData = &sv

	ee := rc.NewExpressionEvaluator(jobExecCtx)
	rc.ExprEval = ee

	formatter.rc = rc
	if actions_step_debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	rc.StepResults = make(map[string]*model.StepResult)

	for i := 0; i < len(steps); i++ {
		rec := protocol.CreateTimelineEntry(rqt.JobID, steps[i].ID, steps[i].String())
		rec.ID = rqt.Steps[i].ID // This allows the actions_runner adapter to work in gitea
		jlogger.Append(rec).Order = int32(i + len(steps))
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
		fcancelctx, fcancel := context.WithCancel(context.Background())
		defer fcancel()
		ctxError := common.WithJobErrorContainer(runner.WithJobLogger(runner.WithJobLoggerFactory(common.WithLogger(fcancelctx, logger), &JobLoggerFactory{Logger: logger}), "", "", runnerConfig, &rc.Masks, rc.Matrix))
		go func() {
			select {
			case <-jobExecCtx.Done():
				<-time.After(5 * time.Minute)
				fcancel()
			case <-fcancelctx.Done():
			}
		}()
		ctxError = context.WithValue(ctxError, common.JobCancelCtxVal, jobExecCtx)
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

func downloadAndExtractAction(ctx context.Context, target string, owner string, name string, resolvedSha string, tarURL string, token string, httpClient *http.Client) (reterr error) {
	cachedTar := filepath.Join(target, "..", owner+"."+name+"."+resolvedSha+".tar")
	defer func() {
		if reterr != nil {
			os.Remove(cachedTar)
		}
	}()
	var tarstream io.Reader
	if fr, err := os.Open(cachedTar); err == nil {
		tarstream = fr
		defer fr.Close()
	} else {
		req, err := http.NewRequestWithContext(ctx, "GET", tarURL, nil)
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Add("Authorization", "token "+token)
		}
		rsp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		defer rsp.Body.Close()
		if len(resolvedSha) == len("0000000000000000000000000000000000000000") {
			fo, err := os.OpenFile(cachedTar, os.O_TRUNC|os.O_CREATE, 0777)
			if err != nil {
				return err
			}
			defer fo.Close()
			len, err := io.Copy(fo, rsp.Body)
			if err != nil {
				return err
			}
			if rsp.ContentLength >= 0 && len != rsp.ContentLength {
				return fmt.Errorf("failed to download tar expected %v, but copied %v", rsp.ContentLength, len)
			}
			tarstream = fo
			fo.Seek(0, 0)
		} else {
			tarstream = rsp.Body
		}
	}
	if err := extractTarGz(tarstream, target); err != nil {
		return err
	}
	return nil
}

func extractTarGz(reader io.Reader, dir string) error {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzr.Close()
	return container.ExtractTar(gzr, dir)
}
