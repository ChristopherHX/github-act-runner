package runnerconfiguration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/google/uuid"
)

func containsEphemeralConfiguration(settings *RunnerSettings) bool {
	if settings == nil {
		return false
	}
	for _, instance := range settings.Instances {
		if instance.Agent != nil && instance.Agent.Ephemeral {
			return true
		}
	}
	return false
}

func (config *ConfigureRunner) Configure(settings *RunnerSettings, survey Survey, auth *protocol.GitHubAuthResult) (*RunnerSettings, error) {
	instance := &RunnerInstance{
		RunnerGuard: config.RunnerGuard,
	}
	if config.Ephemeral && len(settings.Instances) > 0 || containsEphemeralConfiguration(settings) {
		return nil, fmt.Errorf("ephemeral is not supported for multi runners, runner already configured.")
	}
	if len(config.URL) == 0 {
		if !config.Unattended {
			config.URL = survey.GetInput("Please enter your repository, organization or enterprise url:", "")
		} else {
			return nil, fmt.Errorf("no url provided")
		}
	}
	if len(config.URL) == 0 {
		return nil, fmt.Errorf("no url provided")
	}
	instance.RegistrationURL = config.URL
	c := config.GetHttpClient()
	res := auth
	if res == nil {
		authres, err := config.Authenicate(c, survey)
		if err != nil {
			return nil, err
		}
		res = authres
	}

	instance.Auth = res
	vssConnection := &protocol.VssConnection{
		Client:    c,
		TenantURL: res.TenantURL,
		Token:     res.Token,
		Trace:     config.Trace,
	}
	{
		taskAgentPool := ""
		taskAgentPools := []string{}
		_taskAgentPools, err := vssConnection.GetAgentPools()
		if err != nil {
			return nil, fmt.Errorf("failed to configure runner: %v\n", err)
		}
		for _, val := range _taskAgentPools.Value {
			if !val.IsHosted {
				taskAgentPools = append(taskAgentPools, val.Name)
			}
		}
		if len(taskAgentPools) == 0 {
			return nil, fmt.Errorf("failed to configure runner, no self-hosted runner group available")
		}
		if len(config.RunnerGroup) > 0 {
			taskAgentPool = config.RunnerGroup
		} else {
			taskAgentPool = taskAgentPools[0]
			if len(taskAgentPools) > 1 && !config.Unattended {
				taskAgentPool = survey.GetSelectInput("Choose a runner group:", taskAgentPools, taskAgentPool)
			}
		}
		vssConnection.PoolID = -1
		for _, val := range _taskAgentPools.Value {
			if !val.IsHosted && strings.EqualFold(val.Name, taskAgentPool) {
				vssConnection.PoolID = val.ID
			}
		}
		if vssConnection.PoolID < 0 {
			return nil, fmt.Errorf("runner Pool %v not found\n", taskAgentPool)
		}
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	instance.Key = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))

	taskAgent := &protocol.TaskAgent{}
	bs := make([]byte, 4)
	ui := uint32(key.E)
	binary.BigEndian.PutUint32(bs, ui)
	expof := 0
	for ; expof < 3 && bs[expof] == 0; expof++ {
	}
	taskAgent.Authorization.PublicKey = protocol.TaskAgentPublicKey{Exponent: base64.StdEncoding.EncodeToString(bs[expof:]), Modulus: base64.StdEncoding.EncodeToString(key.N.Bytes())}
	taskAgent.Version = "3.0.0" // version, will not use fips crypto if set to 0.0.0 *
	taskAgent.OSDescription = "github-act-runner " + runtime.GOOS + "/" + runtime.GOARCH
	if config.Name != "" {
		taskAgent.Name = config.Name
	} else {
		taskAgent.Name = "golang_" + uuid.NewString()
		if !config.Unattended {
			taskAgent.Name = survey.GetInput("Please enter a name of your new runner:", taskAgent.Name)
		}
	}
	if !config.Unattended && len(config.Labels) == 0 {
		if res := survey.GetInput("Please enter custom labels of your new runner (case insensitive, separated by ','):", ""); len(res) > 0 {
			config.Labels = strings.Split(res, ",")
		}
	}
	systemLabels := make([]string, 0, 3)
	if !config.NoDefaultLabels {
		systemLabels = append(systemLabels, "self-hosted", runtime.GOOS, runtime.GOARCH)
	}
	taskAgent.Labels = make([]protocol.AgentLabel, len(systemLabels)+len(config.SystemLabels)+len(config.Labels))
	for i := 0; i < len(systemLabels); i++ {
		taskAgent.Labels[i] = protocol.AgentLabel{Name: systemLabels[i], Type: "system"}
	}
	for i := 0; i < len(config.SystemLabels); i++ {
		taskAgent.Labels[i+len(systemLabels)] = protocol.AgentLabel{Name: config.SystemLabels[i], Type: "system"}
	}
	for i := 0; i < len(config.Labels); i++ {
		taskAgent.Labels[i+len(systemLabels)+len(config.SystemLabels)] = protocol.AgentLabel{Name: config.Labels[i], Type: "user"}
	}
	taskAgent.MaxParallelism = 1
	taskAgent.ProvisioningState = "Provisioned"
	taskAgent.CreatedOn = time.Now().UTC().Format(protocol.TimestampOutputFormat)
	taskAgent.Ephemeral = config.Ephemeral
	{
		err := vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "POST", map[string]string{
			"poolId": fmt.Sprint(vssConnection.PoolID),
		}, map[string]string{}, taskAgent, taskAgent)
		if err != nil {
			if !config.Replace {
				return nil, fmt.Errorf("failed to create taskAgent: %v\n", err.Error())
			}
			// Try replaceing runner if creation failed
			taskAgents := &protocol.TaskAgents{}
			err := vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "GET", map[string]string{
				"poolId": fmt.Sprint(vssConnection.PoolID),
			}, map[string]string{}, nil, taskAgents)
			if err != nil {
				return nil, fmt.Errorf("failed to update taskAgent: %v\n", err.Error())
			}
			invalid := true
			for i := 0; i < len(taskAgents.Value); i++ {
				if taskAgents.Value[i].Name == taskAgent.Name {
					taskAgent.ID = taskAgents.Value[i].ID
					invalid = false
					break
				}
			}
			if invalid {
				return nil, fmt.Errorf("failed to update taskAgent: Failed to find agent")
			}
			err = vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "PUT", map[string]string{
				"poolId":  fmt.Sprint(vssConnection.PoolID),
				"agentId": fmt.Sprint(taskAgent.ID),
			}, map[string]string{}, taskAgent, taskAgent)
			if err != nil {
				return nil, fmt.Errorf("failed to update taskAgent: %v\n", err.Error())
			}
		}
	}
	instance.Agent = taskAgent
	instance.PoolID = vssConnection.PoolID
	settings.Instances = append(settings.Instances, instance)
	return settings, nil
}

func (config *ConfigureRunner) ReadFromEnvironment() {
	config.ConfigureRemoveRunner.ReadFromEnvironment()
	if !config.Ephemeral {
		if v, ok := common.LookupEnvBool("ACTIONS_RUNNER_INPUT_EPHEMERAL"); ok {
			config.Ephemeral = v
		}
	}
	if len(config.Name) == 0 {
		if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_NAME"); ok {
			config.Name = v
		}
	}
	if len(config.Labels) == 0 {
		if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_LABELS"); ok {
			config.Labels = strings.Split(v, ",")
		}
	}
	if !config.Replace {
		if v, ok := common.LookupEnvBool("ACTIONS_RUNNER_INPUT_REPLACE"); ok {
			config.Replace = v
		}
	}
}
