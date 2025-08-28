package actionsdotnetactcompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/actions-oss/act-cli/pkg/common"
	"github.com/actions-oss/act-cli/pkg/model"
	"github.com/actions-oss/act-cli/pkg/runner"
	"github.com/google/uuid"
	"github.com/rhysd/actionlint"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/ChristopherHX/github-act-runner/actionsrunner"
	rcommon "github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/protocol/logger"
)

const (
	// HTTP and redirects constants
	maxRedirects = 10
	jobTimeout   = 5 * time.Minute
	// File permissions
	directoryPermissions = 0o777
	// Stage constants
	mainStage = "Main"
	// Log prefix constants
	debugPrefix = "##[debug]"
	warnPrefix  = "##[warn]"
	errorPrefix = "##[error]"
	panicPrefix = "##[panic]"
	fatalPrefix = "##[fatal]"
)

type ghaFormatter struct {
	rqt           *protocol.AgentJobRequestMessage
	rc            *runner.RunContext
	logger        *logger.JobLogger
	linefeedregex *regexp.Regexp
	main          bool
	result        *model.StepResult
	ctx           context.Context
}

func flushInternal(rec *protocol.TimelineRecord, res *model.StepResult) {
	switch res.Conclusion {
	case model.StepStatusSuccess:
		rec.Complete("Succeeded")
	case model.StepStatusSkipped:
		rec.Complete("Skipped")
	case model.StepStatusFailure:
		rec.Complete("Failed")
	default:
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
		f.EvaluateStep(f.ctx, next)
		next.Complete("Skipped")
	}
}

func (f *ghaFormatter) EvaluateStep(ctx context.Context, rec *protocol.TimelineRecord) {
	if rec == nil || f.rc == nil || f.rc.ExprEval == nil || ctx == nil {
		return
	}
	rec.Name = f.rc.ExprEval.Interpolate(ctx, rec.Name)
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
		if hasStage && stage != mainStage {
			prefix = stage.(string) + "-"
		}
		stepID = prefix + stepIDArray[0]
	}

	if cur := f.logger.Current(); cur != nil && !f.main && hasStepID {
		f.main = true
		flushInternal(cur, &model.StepResult{Conclusion: model.StepStatusSuccess})
	}
	stepName, hasStepName := entry.Data["step"]
	if cur := f.logger.Current(); hasStepName && hasStepID && cur != nil && cur.RefName != stepID {
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
			f.logger.Insert(&te)
			if cur := f.logger.Current(); cur != nil {
				cur.Start()
			}
			_ = f.logger.Update() // Ignore logger update errors
		} else {
			for {
				next := f.logger.MoveNext()
				f.EvaluateStep(f.ctx, next)
				if next == nil || next.RefName == stepID {
					break
				}
				next.Complete("Skipped")
			}
			if cur := f.logger.Current(); cur != nil {
				cur.Start()
			}
			_ = f.logger.Update() // Ignore logger update errors
		}
	}
	msg := entry.Message
	if f.rqt.MaskHints != nil {
		for _, v := range f.rqt.MaskHints {
			if strings.EqualFold(v.Type, "regex") {
				r, err := regexp.Compile(v.Value)
				if err != nil {
					// TODO precompile regex and log errors
					continue
				}
				msg = r.ReplaceAllString(msg, "***")
			}
		}
	}
	if f.rqt.Variables != nil {
		for _, v := range f.rqt.Variables {
			if v.IsSecret && v.Value != "" && !strings.EqualFold(v.Value, "true") &&
				!strings.EqualFold(v.Value, "false") && !strings.EqualFold(v.Value, "0") && !strings.EqualFold(v.Value, "1") {
				msg = strings.ReplaceAll(msg, v.Value, "***")
			}
		}
	}

	if f.linefeedregex == nil {
		f.linefeedregex = regexp.MustCompile(`(\r\n|\r|\n)`)
	}

	prefix := entry.Time.UTC().Format(protocol.TimestampOutputFormat) + " "
	switch entry.Level {
	case logrus.DebugLevel:
		prefix += debugPrefix
	case logrus.WarnLevel:
		prefix += warnPrefix
	case logrus.ErrorLevel:
		prefix += errorPrefix
	case logrus.PanicLevel:
		prefix += panicPrefix
	case logrus.FatalLevel:
		prefix += fatalPrefix
	case logrus.InfoLevel:
		// No special prefix for info level
	case logrus.TraceLevel:
		prefix += debugPrefix
	}
	command, _ := entry.Data["command"].(string)
	arg, _ := entry.Data["arg"].(string)
	raw, _ := entry.Data["raw"].(string)
	switch strings.ToLower(command) {
	case "group":
		msg = "##[group]" + arg
	case "endgroup":
		msg = "##[endgroup]" + arg
	case "debug":
		msg = arg
	case "warning":
		msg = arg
	case "error":
		msg = arg
	case "ignored":
		msg = raw
	}
	msg = f.linefeedregex.ReplaceAllString(prefix+strings.Trim(msg, "\r\n"), "\n"+prefix)

	b.WriteString(msg)
	b.WriteByte('\n')
	return b.Bytes(), nil
}

type JobLoggerFactory struct {
	Logger *logrus.Logger
}

func (factory *JobLoggerFactory) WithJobLogger() *logrus.Logger {
	jobLogger := logrus.New()
	jobLogger.SetOutput(factory.Logger.Out)
	jobLogger.SetLevel(factory.Logger.Level)
	jobLogger.SetFormatter(factory.Logger.Formatter)
	return jobLogger
}

func ExecWorker(rqt *protocol.AgentJobRequestMessage, wc actionsrunner.WorkerContext) {
	jlogger := wc.Logger()
	jobExecCtx := wc.JobExecCtx()
	actLogger := logrus.New()
	actLogger.SetOutput(jlogger)
	formatter := &ghaFormatter{
		rqt:    rqt,
		logger: jlogger,
		ctx:    jobExecCtx,
	}
	actLogger.SetFormatter(formatter)
	actLogger.Println("Initialize translating the job request to actions-oss/act-cli (nektos/act)")
	vssConnection, vssConnectionData, conErr := rqt.GetConnection("SystemVssConnection")
	if conErr != nil {
		wc.FailInitJob("Failed to initialize Job", conErr.Error())
		return
	}
	if jlogger.Connection != nil {
		vssConnection.Client = jlogger.Connection.Client
		vssConnection.Trace = jlogger.Connection.Trace
	}
	finishJob2 := func(result string, outputs *map[string]protocol.VariableValue) {
		jlogger.TimelineRecords.Value[0].Complete(result)
		_ = jlogger.Logger.Close() // Ignore logger close errors
		jlogger.Finish()
		wc.FinishJob(result, outputs)
	}
	failInitJob := func(message string) {
		wc.FailInitJob("Failed to initialize Job", message)
	}
	secrets := map[string]string{}
	runnerConfig := &runner.Config{}

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
		failInitJob("missing github context in ContextData")
		return
	}
	githubCtx := rawGithubCtx.ToRawObject()
	matrix, err := ConvertMatrixInstance(rqt.ContextData)
	if err != nil {
		failInitJob(err.Error())
		return
	}
	env, err := ConvertEnvironment(rqt.EnvironmentVariables)
	if err != nil {
		failInitJob(err.Error())
		return
	}
	env["ACTIONS_RUNTIME_URL"] = vssConnection.TenantURL
	env["ACTIONS_RUNTIME_TOKEN"] = vssConnection.Token

	if cacheURL, cacheOk := vssConnectionData["CacheServerUrl"]; cacheOk && cacheURL != "" {
		env["ACTIONS_CACHE_URL"] = cacheURL
	}
	if idTokenURL, idTokenOk := vssConnectionData["GenerateIdTokenUrl"]; idTokenOk && idTokenURL != "" {
		env["ACTIONS_ID_TOKEN_REQUEST_URL"] = idTokenURL
		env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = vssConnection.Token
	}
	if resultsServiceURL, resultsOk := vssConnectionData["ResultsServiceUrl"]; resultsOk && resultsServiceURL != "" {
		env["ACTIONS_RESULTS_URL"] = resultsServiceURL
	}
	if pipelinesServiceURL, pipelinesOk := vssConnectionData["PipelinesServiceUrl"]; pipelinesOk && pipelinesServiceURL != "" {
		env["ACTIONS_RUNTIME_URL"] = pipelinesServiceURL
	}
	if usesCacheServiceV2, cacheV2Ok := rqt.Variables["actions_uses_cache_service_v2"]; cacheV2Ok &&
		strings.EqualFold(usesCacheServiceV2.Value, "True") {
		env["ACTIONS_CACHE_SERVICE_V2"] = "True" // bool.TrueString
	}

	defaults, err := ConvertDefaults(rqt.Defaults)
	if err != nil {
		failInitJob(err.Error())
		return
	}
	steps, err := ConvertSteps(rqt.Steps)
	if err != nil {
		failInitJob(err.Error())
		return
	}
	actionsStepDebug := false
	if sd, debugOk := rqt.Variables["ACTIONS_STEP_DEBUG"]; debugOk && (sd.Value == "true" || sd.Value == "1") {
		actionsStepDebug = true
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
	if e, eventErr := json.Marshal(githubCtxMap["event"]); eventErr != nil {
		failInitJob(fmt.Sprintf("cannot convert github.event to json: %w", eventErr))
		return
	} else {
		payload = string(e)
	}
	unixHostPrefix := "unix://"
	// derive from DOCKER_HOST or use custom value from DOCKER_HOST_MOUNT_PATH
	if dockerHostMountPath, ok := os.LookupEnv("DOCKER_HOST_MOUNT_PATH"); ok {
		runnerConfig.ContainerDaemonSocket = dockerHostMountPath
	} else if dockerHost, ok := os.LookupEnv("DOCKER_HOST"); ok && strings.HasPrefix(strings.ToLower(dockerHost), unixHostPrefix) {
		runnerConfig.ContainerDaemonSocket = dockerHost[len(unixHostPrefix):]
	}
	// Non customizable config
	runnerConfig.Secrets = secrets
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
	runnerConfig.GitHubServerURL = githubCtxMap["server_url"].(string)
	runnerConfig.GitHubAPIServerURL = githubCtxMap["api_url"].(string)
	runnerConfig.GitHubGraphQlAPIServerURL = githubCtxMap["graphql_url"].(string)
	runnerConfig.NoSkipCheckout = true // Needed to avoid copy the non exiting working dir
	runnerConfig.AutoRemove = true     // Needed to cleanup always cleanup container
	runnerConfig.ForcePull = true
	runnerConfig.ForceRebuild = true
	// allow downloading actions like older actions/runner using credentials of the redirect url
	downloadActionHTTPClient := *vssConnection.HTTPClient()
	downloadActionHTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if len(via) >= 1 && req.Host != via[0].Host {
			req.Header.Del("Authorization")
		}
		return nil
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
	cacheBase := ActionCacheBase{
		VssConnection: vssConnection,
		Plan:          rqt.Plan,
		GHToken:       runnerConfig.Token,
		HttpClient:    &downloadActionHTTPClient,
		CacheDir:      rc.ActionCacheDir(),
	}
	if viaGit, hasViaGit := rcommon.LookupEnvBool("GITHUB_ACT_RUNNER_DOWNLOAD_ACTIONS_VIA_GIT"); hasViaGit && viaGit {
		runnerConfig.ActionCache = nil
	} else if strings.EqualFold(rqt.MessageType, "RunnerJobRequest") {
		launchEndpoint, hasLaunchEndpoint := rqt.Variables["system.github.launch_endpoint"]
		if hasLaunchEndpoint && launchEndpoint.Value != "" {
			launchCache := &LaunchActionCache{
				ActionCacheBase: cacheBase,
				LaunchEndpoint:  launchEndpoint.Value,
				JobID:           rqt.JobID,
			}
			runnerConfig.ActionCache = launchCache
			defer func() {
				for _, v := range launchCache.delete {
					if removeErr := os.Remove(v); removeErr != nil {
						actLogger.Warnf("Unable to remove %v: %v", v, removeErr)
					}
				}
			}()
		}
	} else {
		vssCache := &VssActionCache{
			ActionCacheBase: cacheBase,
		}
		runnerConfig.ActionCache = vssCache
		defer func() {
			for _, v := range vssCache.delete {
				if removeErr := os.Remove(v); removeErr != nil {
					actLogger.Warnf("Unable to remove %v: %v", v, removeErr)
				}
			}
		}()
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

	ee := rc.NewExpressionEvaluator(jobExecCtx)
	rc.ExprEval = ee

	formatter.rc = rc
	if actionsStepDebug {
		actLogger.SetLevel(logrus.DebugLevel)
	} else {
		actLogger.SetLevel(logrus.InfoLevel)
	}

	rc.StepResults = make(map[string]*model.StepResult)

	eval := rc.NewExpressionEvaluator(jobExecCtx)
	for i := 0; i < len(steps); i++ {
		rec := protocol.CreateTimelineEntry(rqt.JobID, steps[i].ID, steps[i].String())
		rec.ID = rqt.Steps[i].ID // This allows the actions_runner adapter to work in gitea
		parser := actionlint.NewExprParser()
		exprNode, err := parser.Parse(actionlint.NewExprLexer(strings.TrimPrefix(rec.Name, "${{")))
		canEvaluateNow := err == nil
		actionlint.VisitExprNode(exprNode, func(node, _ actionlint.ExprNode, entering bool) {
			if variableNode, ok := node.(*actionlint.VariableNode); entering && ok {
				switch strings.ToLower(variableNode.Name) {
				case "env", "steps", "job":
					canEvaluateNow = false
				}
			}
		})
		if canEvaluateNow {
			rec.Name = eval.Interpolate(jobExecCtx, rec.Name)
		}
		// Check for integer overflow before conversion
		order := i + len(steps) + 1
		if order > math.MaxInt32 { // int32 max value
			order = math.MaxInt32
		}
		jlogger.Append(&rec).Order = int32(order) //nolint:gosec // bounds checked above
	}

	logrus.SetLevel(actLogger.GetLevel())
	logrus.SetFormatter(actLogger.Formatter)
	logrus.SetOutput(actLogger.Out)

	cacheDir := rc.ActionCacheDir()
	if mkdirErr := os.MkdirAll(cacheDir, directoryPermissions); mkdirErr != nil {
		actLogger.Warn("github-act-runner is be unable to access \"" + cacheDir + "\". You might want set one of the " +
			"following environment variables XDG_CACHE_HOME, HOME to a user read and writeable location. Details: " + mkdirErr.Error())
	}
	actLogger.Println("Starting actions-oss/act-cli (nektos/act)")
	select {
	case <-jobExecCtx.Done():
	default:
		fcancelctx, fcancel := context.WithCancel(context.Background())
		defer fcancel()
		ctxError := common.WithJobErrorContainer(
			runner.WithJobLogger(
				runner.WithJobLoggerFactory(
					common.WithLogger(fcancelctx, actLogger), &JobLoggerFactory{Logger: actLogger}),
				"", "", runnerConfig, &rc.Masks, rc.Matrix))
		go func() {
			select {
			case <-jobExecCtx.Done():
				<-time.After(jobTimeout)
				fcancel()
			case <-fcancelctx.Done():
			}
		}()
		ctxError = context.WithValue(ctxError, common.JobCancelCtxVal, jobExecCtx)
		formatter.ctx = ctxError
		var ex common.Executor
		ex, err = rc.Executor()
		if err == nil {
			err = ex(ctxError)
		}
		if err == nil {
			err = common.JobError(ctxError)
		}
	}

	jobStatus := "Succeeded"
	var outputMap *map[string]protocol.VariableValue

	if err != nil {
		actLogger.Logf(logrus.ErrorLevel, "%v", err.Error())
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
