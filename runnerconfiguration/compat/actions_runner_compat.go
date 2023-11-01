package compat

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
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
	AgentId       string `json:"AgentId"`
	AgentName     string `json:"AgentName"`
	DisableUpdate string `json:"DisableUpdate"`
	Ephemeral     string `json:"Ephemeral"`
	PoolId        string `json:"PoolId"`
	PoolName      string `json:"PoolName,omitempty"`
	ServerUrl     string `json:"ServerUrl"`
	WorkFolder    string `json:"WorkFolder"`
	GitHubUrl 	  string `json:"GitHubUrl"`
}

type DotnetCredentials struct {
	Scheme string                `json:"Scheme"`
	Data   DotnetCredentialsData `json:"Data"`
}

type DotnetCredentialsData struct {
	ClientId         string `json:"ClientId"`
	AuthorizationUrl string `json:"AuthorizationUrl"`
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
	return common.ReadJson(name, obj)
}

func (config DefaultConfigFileAccess) Write(name string, obj interface{}) error {
	return common.WriteJson(name, obj)
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
	poolID, err := strconv.ParseInt(agent.PoolId, 10, 64)
	if err != nil {
		return nil, err
	}
	agentID, err := strconv.ParseInt(agent.AgentId, 10, 32)
	if err != nil {
		return nil, err
	}
	ephemeral, _ := strconv.ParseBool(agent.Ephemeral)
	disableUpdate, _ := strconv.ParseBool(agent.DisableUpdate)
	return &runnerconfiguration.RunnerInstance{
		PoolID: poolID,
		Auth: &protocol.GitHubAuthResult{
			TenantURL: agent.ServerUrl,
		},
		PKey: FromRsaParameters(rsaParameters),
		Agent: &protocol.TaskAgent{
			ID:             int(agentID),
			Ephemeral:      ephemeral,
			Name:           agent.AgentName,
			MaxParallelism: 1,
			Authorization: protocol.TaskAgentAuthorization{
				AuthorizationURL: credentials.Data.AuthorizationUrl,
				ClientID:         credentials.Data.ClientId,
			},
			DisableUpdate: disableUpdate,
		},
		WorkFolder: agent.WorkFolder,
		RegistrationURL: agent.GitHubUrl,
	}, nil
}

func FromRunnerInstance(instance *runnerconfiguration.RunnerInstance, fileAccess ConfigFileAccess) error {
	agent := &DotnetAgent{
		AgentId:       fmt.Sprint(instance.Agent.ID),
		AgentName:     instance.Agent.Name,
		Ephemeral:     fmt.Sprint(instance.Agent.Ephemeral),
		DisableUpdate: fmt.Sprint(instance.Agent.DisableUpdate),
		PoolId:        fmt.Sprint(instance.PoolID),
		ServerUrl:     instance.Auth.TenantURL,
		WorkFolder:    instance.WorkFolder,
		GitHubUrl:     instance.RegistrationURL,
	}
	if agent.WorkFolder == "" {
		agent.WorkFolder = "_work"
	}
	credentials := &DotnetCredentials{
		Scheme: "OAuth",
		Data: DotnetCredentialsData{
			ClientId:         instance.Agent.Authorization.ClientID,
			AuthorizationUrl: instance.Agent.Authorization.AuthorizationURL,
		},
	}
	if err := fileAccess.Write(".runner", agent); err != nil {
		return err
	}
	if err := fileAccess.Write(".credentials", credentials); err != nil {
		return err
	}
	if err := instance.EnshurePKey(); err != nil {
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
	if err := json.Unmarshal(rawfiles, &files); err != nil {
		return nil, err
	}
	ret, err := ToRunnerInstance(JITConfigFileAccess(files))
	ToXmlString(&ret.PKey.PublicKey)
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

type RSAKeyValue struct {
	Modulus  string
	Exponent string
}

func ToXmlString(publicKey *rsa.PublicKey) (string, error) {
	res, err := xml.Marshal(&RSAKeyValue{
		Modulus:  base64.StdEncoding.EncodeToString(publicKey.N.Bytes()),
		Exponent: base64.StdEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	})
	return string(res), err
}
