package compat

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/runnerconfiguration"
)

type DotnetRsaParameters struct {
	D        []byte `json:"d"`
	DP       []byte `json:"dp"`
	DQ       []byte `json:"dq"`
	Exponent []byte `json:"exponent"`
	InverseQ []byte `json:"inverseQ"`
	Modulus  []byte `json:"modulus"`
	P        []byte `json:"p"`
	Q        []byte `json:"q"`
}

type DotnetAgent struct {
	AgentID       string `json:"AgentId"`
	AgentName     string `json:"AgentName"`
	DisableUpdate string `json:"DisableUpdate"`
	Ephemeral     string `json:"Ephemeral"`
	PoolID        string `json:"PoolId"`
	PoolName      string `json:"PoolName,omitempty"`
	ServerURL     string `json:"ServerUrl"`
	WorkFolder    string `json:"WorkFolder"`
	GitHubURL     string `json:"GitHubUrl"`
	UseV2Flow     bool   `json:"UseV2Flow"`
	ServerURLV2   string `json:"ServerUrlV2"`
}

type DotnetCredentials struct {
	Scheme string                `json:"Scheme"`
	Data   DotnetCredentialsData `json:"Data"`
}

type DotnetCredentialsData struct {
	ClientID         string `json:"ClientId"`
	AuthorizationURL string `json:"AuthorizationUrl"`
}

func BytesToBigInt(bytes []byte) *big.Int {
	ret := &big.Int{}
	ret.SetBytes(bytes)
	return ret
}

func FromRsaParameters(param *DotnetRsaParameters) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		D: BytesToBigInt(param.D),
		Primes: []*big.Int{
			BytesToBigInt(param.P),
			BytesToBigInt(param.Q),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:   BytesToBigInt(param.DP),
			Dq:   BytesToBigInt(param.DQ),
			Qinv: BytesToBigInt(param.InverseQ),
		},
		PublicKey: rsa.PublicKey{
			N: BytesToBigInt(param.Modulus),
			E: int(BytesToBigInt(param.Exponent).Int64()),
		},
	}
}

func ToRsaParameters(key *rsa.PrivateKey) *DotnetRsaParameters {
	return &DotnetRsaParameters{
		D:        key.D.Bytes(),
		P:        key.Primes[0].Bytes(),
		Q:        key.Primes[1].Bytes(),
		DP:       key.Precomputed.Dp.Bytes(),
		DQ:       key.Precomputed.Dq.Bytes(),
		InverseQ: key.Precomputed.Qinv.Bytes(),
		Modulus:  key.N.Bytes(),
		Exponent: big.NewInt(int64(key.E)).Bytes(),
	}
}

type ConfigFileAccess interface {
	Read(name string, obj interface{}) error
	Write(name string, obj interface{}) error
}

type DefaultConfigFileAccess struct{}

func (config DefaultConfigFileAccess) Read(name string, obj interface{}) error {
	return common.ReadJSON(name, obj)
}

func (config DefaultConfigFileAccess) Write(name string, obj interface{}) error {
	return common.WriteJSON(name, obj)
}

type JITConfigFileAccess map[string][]byte

func (config JITConfigFileAccess) Read(name string, obj interface{}) error {
	return json.Unmarshal(config[name], obj)
}

func (config JITConfigFileAccess) Write(name string, obj interface{}) error {
	storage, err := json.Marshal(obj)
	if err == nil {
		config[name] = storage
	}
	return err
}

func ToRunnerInstance(fileAccess ConfigFileAccess) (*runnerconfiguration.RunnerInstance, error) {
	agent := &DotnetAgent{}
	if err := fileAccess.Read(".runner", agent); err != nil {
		return nil, err
	}
	credentials := &DotnetCredentials{}
	if err := fileAccess.Read(".credentials", credentials); err != nil {
		return nil, err
	}
	rsaParameters := &DotnetRsaParameters{}
	if err := fileAccess.Read(".credentials_rsaparams", rsaParameters); err != nil {
		return nil, err
	}
	poolID, err := strconv.ParseInt(agent.PoolID, 10, 64)
	if err != nil {
		return nil, err
	}
	agentID, err := strconv.ParseInt(agent.AgentID, 10, 64)
	if err != nil {
		return nil, err
	}
	ephemeral, _ := strconv.ParseBool(agent.Ephemeral)
	disableUpdate, _ := strconv.ParseBool(agent.DisableUpdate)
	return &runnerconfiguration.RunnerInstance{
		PoolID: poolID,
		Auth: &protocol.GitHubAuthResult{
			TenantURL: agent.ServerURL,
		},
		PKey: FromRsaParameters(rsaParameters),
		Agent: &protocol.TaskAgent{
			ID:             agentID,
			Ephemeral:      ephemeral,
			Name:           agent.AgentName,
			MaxParallelism: 1,
			Authorization: protocol.TaskAgentAuthorization{
				AuthorizationURL: credentials.Data.AuthorizationURL,
				ClientID:         credentials.Data.ClientID,
			},
			DisableUpdate: disableUpdate,
			Version:       "3.0.0",
			ServerV2URL:   agent.ServerURLV2,
		},
		WorkFolder:      agent.WorkFolder,
		RegistrationURL: agent.GitHubURL,
	}, nil
}

func FromRunnerInstance(instance *runnerconfiguration.RunnerInstance, fileAccess ConfigFileAccess) error {
	agent := &DotnetAgent{
		AgentID:       fmt.Sprint(instance.Agent.ID),
		AgentName:     instance.Agent.Name,
		Ephemeral:     fmt.Sprint(instance.Agent.Ephemeral),
		DisableUpdate: fmt.Sprint(instance.Agent.DisableUpdate),
		PoolID:        fmt.Sprint(instance.PoolID),
		ServerURL:     instance.Auth.TenantURL,
		WorkFolder:    instance.WorkFolder,
		GitHubURL:     instance.RegistrationURL,
		UseV2Flow:     instance.Auth.UseV2FLow,
		ServerURLV2:   instance.Agent.ServerV2URL,
	}
	if agent.WorkFolder == "" {
		agent.WorkFolder = "_work"
	}
	credentials := &DotnetCredentials{
		Scheme: "OAuth",
		Data: DotnetCredentialsData{
			ClientID:         instance.Agent.Authorization.ClientID,
			AuthorizationURL: instance.Agent.Authorization.AuthorizationURL,
		},
	}
	if err := fileAccess.Write(".runner", agent); err != nil {
		return err
	}
	if err := fileAccess.Write(".credentials", credentials); err != nil {
		return err
	}
	if err := instance.EnsurePKey(); err != nil {
		return err
	}
	if err := fileAccess.Write(".credentials_rsaparams", ToRsaParameters(instance.PKey)); err != nil {
		return err
	}
	return nil
}

func ParseJitRunnerConfig(conf string) (*runnerconfiguration.RunnerSettings, error) {
	rawfiles, err := base64.StdEncoding.DecodeString(conf)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	if unmarshalErr := json.Unmarshal(rawfiles, &files); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	ret, err := ToRunnerInstance(JITConfigFileAccess(files))
	return &runnerconfiguration.RunnerSettings{
		Instances: []*runnerconfiguration.RunnerInstance{
			ret,
		},
	}, err
}

func ToJitRunnerConfig(instance *runnerconfiguration.RunnerInstance) (string, error) {
	files := map[string][]byte{}
	if err := FromRunnerInstance(instance, JITConfigFileAccess(files)); err != nil {
		return "", err
	}
	rawfiles, err := json.Marshal(&files)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rawfiles), nil
}
