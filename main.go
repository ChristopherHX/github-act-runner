package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	// "github.com/AlecAivazis/survey/v2"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	_ "github.com/mtibben/androiddnsfix"
	"github.com/nektos/act/pkg/common"
	"github.com/nektos/act/pkg/container"
	"github.com/nektos/act/pkg/model"
	"github.com/nektos/act/pkg/runner"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type RunnerAddRemove struct {
	Url         string `json:"url"`
	RunnerEvent string `json:"runner_event"`
}

type GitHubRunnerRegisterToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type GitHubAuthResult struct {
	TenantUrl   string `json:"url"`
	TokenSchema string `json:"token_schema"`
	Token       string `json:"token"`
}

type ServiceDefinition struct {
	ServiceType       string
	Identifier        string
	DisplayName       string
	RelativeToSetting int
	RelativePath      string
	Description       string
	ServiceOwner      string
	ResourceVersion   int
}

type LocationServiceData struct {
	ServiceDefinitions []ServiceDefinition
}

type ConnectionData struct {
	LocationServiceData LocationServiceData
}

type TaskAgentPoolReference struct {
	Id         int64
	Scope      string
	PoolType   int
	Name       string
	IsHosted   bool
	IsInternal bool
	Size       int64
}

type TaskAgentPool struct {
	TaskAgentPoolReference
}

type TaskAgents struct {
	Count int64
	Value []TaskAgent
}

type TaskAgentPools struct {
	Count int64
	Value []TaskAgentPool
}

type TaskAgentPublicKey struct {
	Exponent string
	Modulus  string
}

type TaskAgentAuthorization struct {
	AuthorizationUrl string `json:",omitempty"`
	ClientId         string `json:",omitempty"`
	PublicKey        TaskAgentPublicKey
}

type AgentLabel struct {
	Id   int
	Name string
	Type string
}

type TaskAgent struct {
	Authorization     TaskAgentAuthorization
	Labels            []AgentLabel
	MaxParallelism    int
	Id                int
	Name              string
	Version           string
	OSDescription     string
	Enabled           *bool `json:",omitempty"`
	ProvisioningState string
	AccessPoint       string `json:",omitempty"`
	CreatedOn         string
}

type TaskLogReference struct {
	Id       int
	Location *string
}

type TaskLog struct {
	TaskLogReference
	IndexLocation *string `json:",omitempty"`
	Path          *string `json:",omitempty"`
	LineCount     *int64  `json:",omitempty"`
	CreatedOn     string
	LastChangedOn string
}

type TimeLineReference struct {
	Id       string
	ChangeId int
	Location *interface{}
}

type Issue struct {
}

type TimelineAttempt struct {
}

type VariableValue struct {
	Value    string
	IsSecret bool
}

type TimelineRecord struct {
	Id               string
	TimelineId       string
	ParentId         string
	Type             string
	Name             string
	StartTime        string
	FinishTime       *string
	CurrentOperation *string
	PercentComplete  int32
	State            string
	Result           *string
	ResultCode       *string
	ChangeId         int32
	LastModified     string
	WorkerName       string
	Order            int32
	RefName          string
	Log              *TaskLogReference
	Details          *TimeLineReference
	ErrorCount       int
	WarningCount     int
	Issues           []Issue
	Location         string
	Attempt          int32
	Identifier       *string
	AgentPlatform    string
	PreviousAttempts []TimelineAttempt
	Variables        map[string]VariableValue
}

type TaskOrchestrationPlanReference struct {
	ScopeIdentifier string
	PlanId          string
	PlanType        string
}

type MapEntry struct {
	Key   *TemplateToken
	Value *TemplateToken
}

type TemplateToken struct {
	FileId    *int32
	Line      *int32
	Column    *int32
	Type      int32
	Bool      *bool
	Num       *float64
	Lit       *string
	Expr      *string
	Directive *string
	Seq       *[]TemplateToken
	Map       *[]MapEntry
}

func (token *TemplateToken) UnmarshalJSON(data []byte) error {
	if json.Unmarshal(data, &token.Bool) == nil {
		token.Type = 5
		return nil
	} else if json.Unmarshal(data, &token.Num) == nil {
		token.Bool = nil
		token.Type = 6
		return nil
	} else if json.Unmarshal(data, &token.Lit) == nil {
		token.Bool = nil
		token.Num = nil
		token.Type = 0
		return nil
	} else {
		token.Bool = nil
		token.Num = nil
		token.Lit = nil
		type TemplateToken2 TemplateToken
		return json.Unmarshal(data, (*TemplateToken2)(token))
	}
}

func (token *TemplateToken) FromRawObject(value interface{}) {
	switch val := value.(type) {
	case string:
		// TODO: We may need to restore expressions "${{abc}}" to expression objects
		token.Type = 0
		token.Lit = &val
	case []interface{}:
		token.Type = 1
		a := val
		seq := make([]TemplateToken, len(a))
		token.Seq = &seq
		for i, v := range a {
			e := TemplateToken{}
			e.FromRawObject(v)
			(*token.Seq)[i] = e
		}
	case map[interface{}]interface{}:
		token.Type = 2
		_map := make([]MapEntry, 0)
		token.Map = &_map
		for k, v := range val {
			key := &TemplateToken{}
			key.FromRawObject(k)
			value := &TemplateToken{}
			value.FromRawObject(v)
			_map = append(_map, MapEntry{
				Key:   key,
				Value: value,
			})
		}
	case bool:
		token.Type = 5
		token.Bool = &val
	case float64:
		token.Type = 6
		token.Num = &val
	}
}

func (token *TemplateToken) ToRawObject() interface{} {
	switch token.Type {
	case 0:
		return *token.Lit
	case 1:
		a := make([]interface{}, 0)
		for _, v := range *token.Seq {

			a = append(a, v.ToRawObject())
		}
		return a
	case 2:
		m := make(map[interface{}]interface{})
		for _, v := range *token.Map {
			m[v.Key.ToRawObject()] = v.Value.ToRawObject()
		}
		return m
	case 3:
		return "${{" + *token.Expr + "}}"
	case 4:
		return *token.Directive
	case 5:
		return *token.Bool
	case 6:
		return *token.Num
	}
	return nil
}

func (token *TemplateToken) ToYamlNode() *yaml.Node {
	switch token.Type {
	case 0:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: *token.Lit}
	case 1:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Seq {

			a = append(a, v.ToYamlNode())
		}
		return &yaml.Node{Kind: yaml.SequenceNode, Content: a}
	case 2:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Map {
			a = append(a, v.Key.ToYamlNode(), v.Value.ToYamlNode())
		}
		return &yaml.Node{Kind: yaml.MappingNode, Content: a}
	case 3:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: "${{" + *token.Expr + "}}"}
	case 4:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: *token.Directive}
	case 5:
		val, _ := yaml.Marshal(token.Bool)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}
	case 6:
		val, _ := yaml.Marshal(token.Num)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}
	case 7:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: "null"}
	}
	return nil
}

type JobAuthorization struct {
	Parameters map[string]string
	Scheme     string
}

type JobEndpoint struct {
	Data          map[string]string
	Name          string
	Url           string
	Authorization JobAuthorization
	IsShared      bool
	IsReady       bool
}

type JobResources struct {
	Endpoints []JobEndpoint
}

type DictionaryContextDataPair struct {
	Key   string              `json:"k"`
	Value PipelineContextData `json:"v"`
}

type PipelineContextData struct {
	Type            *int32                       `json:"t,omitempty"`
	BoolValue       *bool                        `json:"b,omitempty"`
	NumberValue     *float64                     `json:"n,omitempty"`
	StringValue     *string                      `json:"s,omitempty"`
	ArrayValue      *[]PipelineContextData       `json:"a,omitempty"`
	DictionaryValue *[]DictionaryContextDataPair `json:"d,omitempty"`
}

func (ctx *PipelineContextData) UnmarshalJSON(data []byte) error {
	if json.Unmarshal(data, &ctx.BoolValue) == nil {
		if ctx.BoolValue == nil {
			ctx = nil
		} else {
			var typ int32 = 3
			ctx.Type = &typ
		}
		return nil
	} else if json.Unmarshal(data, &ctx.NumberValue) == nil {
		ctx.BoolValue = nil
		var typ int32 = 4
		ctx.Type = &typ
		return nil
	} else if json.Unmarshal(data, &ctx.StringValue) == nil {
		ctx.BoolValue = nil
		ctx.NumberValue = nil
		var typ int32 = 0
		ctx.Type = &typ
		return nil
	} else {
		ctx.BoolValue = nil
		ctx.NumberValue = nil
		ctx.StringValue = nil
		type PipelineContextData2 PipelineContextData
		return json.Unmarshal(data, (*PipelineContextData2)(ctx))
	}
}

func (ctx PipelineContextData) ToRawObject() interface{} {
	if ctx.Type == nil {
		return nil
	}
	switch *ctx.Type {
	case 0:
		return *ctx.StringValue
	case 1:
		a := make([]interface{}, 0)
		if ctx.ArrayValue != nil {
			for _, v := range *ctx.ArrayValue {
				a = append(a, v.ToRawObject())
			}
		}
		return a
	case 2:
		m := make(map[string]interface{})
		if ctx.DictionaryValue != nil {
			for _, v := range *ctx.DictionaryValue {
				m[v.Key] = v.Value.ToRawObject()
			}
		}
		return m
	case 3:
		return *ctx.BoolValue
	case 4:
		return *ctx.NumberValue
	}
	return nil
}

type WorkspaceOptions struct {
	Clean *string `json:",omitempty"`
}

type MaskHint struct {
	Type  string
	Value string
}

type ActionsEnvironmentReference struct {
	Name *string `json:",omitempty"`
	Url  *string `json:",omitempty"`
}

type ActionStepDefinitionReference struct {
	Type           string
	Image          string
	Name           string
	Ref            string
	RepositoryType string
	Path           string
}

type ActionStep struct {
	Type             string
	Reference        ActionStepDefinitionReference
	DisplayNameToken *TemplateToken
	ContextName      string
	Environment      *TemplateToken
	Inputs           *TemplateToken
	Condition        string
	ContinueOnError  *TemplateToken
	TimeoutInMinutes *TemplateToken
}

type AgentJobRequestMessage struct {
	MessageType          string
	Plan                 *TaskOrchestrationPlanReference
	Timeline             *TimeLineReference
	JobId                string
	JobDisplayName       string
	JobName              string
	JobContainer         *TemplateToken
	JobServiceContainers *TemplateToken
	JobOutputs           *TemplateToken
	RequestId            int64
	LockedUntil          string
	Resources            *JobResources
	ContextData          map[string]PipelineContextData
	Workspace            *WorkspaceOptions
	MaskHints            []MaskHint `json:"mask"`
	EnvironmentVariables []TemplateToken
	Defaults             []TemplateToken
	ActionsEnvironment   *ActionsEnvironmentReference
	Variables            map[string]VariableValue
	Steps                []ActionStep
	FileTable            []string
}

type RenewAgent struct {
	RequestId int64
}

type TaskAgentMessage struct {
	MessageId   int64
	MessageType string
	IV          string
	Body        string
}

type TaskAgentSessionKey struct {
	Encrypted bool
	Value     string
}

type TaskAgentSession struct {
	SessionId         string `json:",omitempty"`
	EncryptionKey     TaskAgentSessionKey
	OwnerName         string
	Agent             TaskAgent
	UseFipsEncryption bool
}

func (session *TaskAgentSession) GetSessionKey(key *rsa.PrivateKey) (cipher.Block, error) {
	sessionKey, err := base64.StdEncoding.DecodeString(session.EncryptionKey.Value)
	if sessionKey == nil || err != nil {
		return nil, err
	}
	if session.EncryptionKey.Encrypted {
		var h hash.Hash
		if session.UseFipsEncryption {
			h = sha256.New()
		} else {
			h = sha1.New()
		}
		sessionKey, err = rsa.DecryptOAEP(h, rand.Reader, key, sessionKey, []byte{})
		if sessionKey == nil || err != nil {
			return nil, err
		}
	}
	return aes.NewCipher(sessionKey)
}

type VssOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type TimelineRecordWrapper struct {
	Count int64
	Value []TimelineRecord
}

type TimelineRecordFeedLinesWrapper struct {
	Count     int32
	Value     []string
	StepId    string
	StartLine *int64
}

type JobEvent struct {
	Name               string
	JobId              string
	RequestId          int64
	Result             string
	Outputs            *map[string]VariableValue    `json:",omitempty"`
	ActionsEnvironment *ActionsEnvironmentReference `json:",omitempty"`
}

func (rec *TimelineRecord) Start() {
	time := time.Now().UTC().Format("2006-01-02T15:04:05")
	rec.PercentComplete = 0
	rec.State = "InProgress"
	rec.StartTime = time
	rec.FinishTime = nil
	rec.LastModified = time
}

func (rec *TimelineRecord) Complete(res string) {
	time := time.Now().UTC().Format("2006-01-02T15:04:05")
	rec.PercentComplete = 100
	rec.State = "Completed"
	rec.FinishTime = &time
	rec.LastModified = time
	rec.Result = &res
}

func CreateTimelineEntry(parent string, refname string, name string) TimelineRecord {
	record := TimelineRecord{}
	record.Id = uuid.New().String()
	record.RefName = refname
	record.Name = name
	record.Type = "Task"
	record.WorkerName = "golang-go"
	record.ParentId = parent
	record.State = "Pending"
	record.LastModified = time.Now().UTC().Format("2006-01-02T15:04:05")
	record.Order = 1
	return record
}

func (vssConnection *VssConnection) GetConnectionData() *ConnectionData {
	_url, _ := url.Parse(vssConnection.TenantUrl)
	_url.Path = path.Join(_url.Path, "_apis/connectionData")
	q := _url.Query()
	q.Add("connectOptions", "1")
	q.Add("lastChangeId", "-1")
	q.Add("lastChangeId64", "-1")
	_url.RawQuery = q.Encode()
	connectionData, _ := http.NewRequest("GET", _url.String(), nil)
	connectionDataResp, err := vssConnection.Client.Do(connectionData)
	connectionData_ := &ConnectionData{}
	if err != nil {
		fmt.Println("fatal:" + err.Error())
		return nil
	}
	defer connectionDataResp.Body.Close()
	dec2 := json.NewDecoder(connectionDataResp.Body)
	dec2.Decode(connectionData_)
	return connectionData_
}

func (vssConnection *VssConnection) BuildUrl(relativePath string, ppath map[string]string, query map[string]string) string {
	url2, _ := url.Parse(vssConnection.TenantUrl)
	url := relativePath
	for p, v := range ppath {
		url = strings.ReplaceAll(url, "{"+p+"}", v)
	}
	re := regexp.MustCompile(`/*\{[^\}]+\}`)
	url = re.ReplaceAllString(url, "")
	url2.Path = path.Join(url2.Path, url)
	q := url2.Query()
	for p, v := range query {
		q.Add(p, v)
	}
	url2.RawQuery = q.Encode()
	return url2.String()
}

func (connectionData *ConnectionData) GetServiceDefinition(id string) *ServiceDefinition {
	for i := 0; i < len(connectionData.LocationServiceData.ServiceDefinitions); i++ {
		if connectionData.LocationServiceData.ServiceDefinitions[i].Identifier == id {
			return &connectionData.LocationServiceData.ServiceDefinitions[i]
		}
	}
	return nil
}

type VssConnection struct {
	Client         *http.Client
	TenantUrl      string
	ConnectionData *ConnectionData
	Token          string
	Settings       *RunnerSettings
	TaskAgent      *TaskAgent
	Key            *rsa.PrivateKey
	Trace          bool
}

type AgentMessageConnection struct {
	VssConnection    *VssConnection
	TaskAgentSession *TaskAgentSession
	Block            cipher.Block
}

func (vssConnection *VssConnection) authorize() (*VssOAuthTokenResponse, error) {
	var authResponse *VssOAuthTokenResponse
	var err error
	for i := 0; i < 5; i++ {
		authResponse, err = vssConnection.TaskAgent.Authorize(vssConnection.Client, vssConnection.Key)
		if err == nil {
			return authResponse, nil
		}
		<-time.After(30 * time.Second)
	}
	return nil, err
}

func (vssConnection *VssConnection) Request(serviceId string, protocol string, method string, urlParameter map[string]string, queryParameter map[string]string, requestBody interface{}, responseBody interface{}) error {
	return vssConnection.RequestWithContext(context.Background(), serviceId, protocol, method, urlParameter, queryParameter, requestBody, responseBody)
}
func (vssConnection *VssConnection) RequestWithContext(ctx context.Context, serviceId string, protocol string, method string, urlParameter map[string]string, queryParameter map[string]string, requestBody interface{}, responseBody interface{}) error {
	serv := vssConnection.ConnectionData.GetServiceDefinition(serviceId)
	if urlParameter == nil {
		urlParameter = map[string]string{}
	}
	urlParameter["area"] = serv.ServiceType
	urlParameter["resource"] = serv.DisplayName
	if queryParameter == nil {
		queryParameter = map[string]string{}
	}
	url := vssConnection.BuildUrl(serv.RelativePath, urlParameter, queryParameter)
	for i := 0; i < 2; i++ {
		var buf io.Reader = nil
		if requestBody != nil {
			if _buf, ok := requestBody.(*bytes.Buffer); ok {
				buf = _buf
			} else {
				_buf := new(bytes.Buffer)
				enc := json.NewEncoder(_buf)
				if err := enc.Encode(requestBody); err != nil {
					return err
				}
				buf = _buf
			}
		}
		request, err := http.NewRequestWithContext(ctx, method, url, buf)
		if err != nil {
			return err
		}
		if len(protocol) > 0 {
			AddContentType(request.Header, protocol)
		}
		AddHeaders(request.Header)
		if vssConnection.Trace {
			headerbuf := new(bytes.Buffer)
			request.Header.Write(headerbuf)
			body := ""
			if _buf, ok := buf.(*bytes.Buffer); ok {
				body = _buf.String()
			}
			fmt.Printf("Http %v Request started %v Headers: %v Body: `%v`\n", method, url, headerbuf.String(), body)
		}
		AddBearer(request.Header, vssConnection.Token)

		response, err := vssConnection.Client.Do(request)
		if err != nil {
			return err
		}
		if response == nil {
			return fmt.Errorf("failed to send request response is nil")
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			if i == 0 && (response.StatusCode == 401 || response.StatusCode == 400) && vssConnection.TaskAgent != nil && vssConnection.Key != nil {
				authResponse, err := vssConnection.authorize()
				if err != nil {
					return err
				}
				vssConnection.Token = authResponse.AccessToken
				continue
			}
			body := ""
			if _buf, ok := buf.(*bytes.Buffer); ok {
				body = _buf.String()
			}
			bytes, err := ioutil.ReadAll(response.Body)
			if err != nil {
				bytes = []byte("no response: " + err.Error())
			}
			return fmt.Errorf("request %v %v failed with status %v, requestBody: `%v` and responseBody: `%v`", method, url, response.StatusCode, body, string(bytes))
		}
		if responseBody != nil {
			if response.StatusCode != 200 {
				return io.EOF
			}
			if vssConnection.Trace {
				headerbuf := new(bytes.Buffer)
				request.Header.Write(headerbuf)
				bytes, err := ioutil.ReadAll(response.Body)
				if err != nil {
					bytes = []byte("no response: " + err.Error())
				}
				fmt.Printf("Http %v Request succeeded %v Headers: %v Body: `%v`\n", method, url, headerbuf.String(), string(bytes))

				if err := json.Unmarshal(bytes, responseBody); err != nil {
					return err
				}
			} else {
				dec := json.NewDecoder(response.Body)
				if err := dec.Decode(responseBody); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return fmt.Errorf("failed to send request unable to authenticate")
}

func (vssConnection *VssConnection) GetAgentPools() (*TaskAgentPools, error) {
	_taskAgentPools := &TaskAgentPools{}
	if err := vssConnection.Request("a8c47e17-4d56-4a56-92bb-de7ea7dc65be", "", "GET", map[string]string{}, map[string]string{}, nil, _taskAgentPools); err != nil {
		return nil, err
	}
	return _taskAgentPools, nil
}
func (vssConnection *VssConnection) CreateSession() (*AgentMessageConnection, error) {
	session := &TaskAgentSession{}
	session.Agent = *vssConnection.TaskAgent
	session.UseFipsEncryption = false // Have to be set to false for "GitHub Enterprise Server 3.0.11", github.com reset it to false 24-07-2021
	session.OwnerName = "RUNNER"
	if err := vssConnection.Request("134e239e-2df3-4794-a6f6-24f1f19ec8dc", "5.1-preview", "POST", map[string]string{
		"poolId": fmt.Sprint(vssConnection.Settings.PoolId),
	}, map[string]string{}, session, session); err != nil {
		return nil, err
	}
	con := &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}
	var err error
	con.Block, err = con.TaskAgentSession.GetSessionKey(vssConnection.Key)
	if err != nil {
		con.Delete()
		return nil, err
	}
	return con, nil
}

func (vssConnection *VssConnection) LoadSession(session *TaskAgentSession) (*AgentMessageConnection, error) {
	return &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}, nil
}

func (session *AgentMessageConnection) Delete() error {
	return session.VssConnection.Request("134e239e-2df3-4794-a6f6-24f1f19ec8dc", "5.1-preview", "DELETE", map[string]string{
		"poolId":    fmt.Sprint(session.VssConnection.Settings.PoolId),
		"sessionId": session.TaskAgentSession.SessionId,
	}, map[string]string{}, session.TaskAgentSession, nil)
}

func AddHeaders(header http.Header) {
	header["X-VSS-E2EID"] = []string{"7f1c293d-97ce-4c59-9e4b-0677c85b8144"}
	header["X-TFS-FedAuthRedirect"] = []string{"Suppress"}
	header["X-TFS-Session"] = []string{"0a6ba747-926b-4ba3-a852-00ab5b5b071a"}
}

// func AddHeaders(header http.Header) {
// 	header["X-VSS-E2EID"] = []string{uuid.NewString()}
// 	header["X-TFS-FedAuthRedirect"] = []string{"Suppress"}
// 	header["X-TFS-Session"] = []string{uuid.NewString()}
// }

func AddContentType(header http.Header, apiversion string) {
	header["Content-Type"] = []string{"application/json; charset=utf-8; api-version=" + apiversion}
	header["Accept"] = []string{"application/json; api-version=" + apiversion}
}

func AddBearer(header http.Header, token string) {
	header["Authorization"] = []string{"bearer " + token}
}

func (vssConnection *VssConnection) UpdateTimeLine(timelineId string, jobreq *AgentJobRequestMessage, wrap *TimelineRecordWrapper) error {
	return vssConnection.Request("8893bc5b-35b2-4be7-83cb-99e683551db4", "5.1-preview", "PATCH", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanId,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineId,
	}, map[string]string{}, wrap, nil)
}

func (vssConnection *VssConnection) UploadLogFile(timelineId string, jobreq *AgentJobRequestMessage, logContent string) int {
	log := &TaskLog{}
	p := "logs/" + uuid.NewString()
	log.Path = &p
	log.CreatedOn = time.Now().UTC().Format("2006-01-02T15:04:05")
	log.LastChangedOn = time.Now().UTC().Format("2006-01-02T15:04:05")

	vssConnection.Request("46f5667d-263a-4684-91b1-dff7fdcf64e2", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanId,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineId,
	}, map[string]string{}, log, log)
	vssConnection.Request("46f5667d-263a-4684-91b1-dff7fdcf64e2", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanId,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineId,
		"logId":           fmt.Sprint(log.Id),
	}, map[string]string{}, bytes.NewBufferString(logContent), nil)
	return log.Id
}

func (vssConnection *VssConnection) DeleteAgent(taskAgent *TaskAgent) error {
	return vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "DELETE", map[string]string{
		"poolId":  fmt.Sprint(vssConnection.Settings.PoolId),
		"agentId": fmt.Sprint(taskAgent.Id),
	}, map[string]string{}, nil, nil)
}

func (vssConnection *VssConnection) FinishJob(e *JobEvent, jobrun *JobRun) error {
	return vssConnection.Request("557624af-b29e-4c20-8ab0-0399d2204f3f", "2.0-preview.1", "POST", map[string]string{
		"scopeIdentifier": jobrun.Plan.ScopeIdentifier,
		"planId":          jobrun.Plan.PlanId,
		"hubName":         jobrun.Plan.PlanType,
	}, map[string]string{}, e, nil)
}

type ghaFormatter struct {
	rqt            *AgentJobRequestMessage
	rc             *runner.RunContext
	wrap           *TimelineRecordWrapper
	current        *TimelineRecord
	updateTimeLine func()
	logline        func(startLine int64, recordId string, line string)
	uploadLogFile  func(log string) int
	startLine      int64
	stepBuffer     *bytes.Buffer
}

func (f *ghaFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}

	if f.current == nil || f.current.RefName != f.rc.CurrentStep {
		res, ok := f.rc.StepResults[f.current.RefName]
		if ok {
			f.startLine = 1
			if f.current != nil {
				if res.Success {
					f.current.Complete("Succeeded")
				} else {
					f.current.Complete("Failed")
				}
				if f.stepBuffer.Len() > 0 {
					f.current.Log = &TaskLogReference{Id: f.uploadLogFile(f.stepBuffer.String())}
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

	entry.Message = strings.Trim(entry.Message, "\r\n")
	b.WriteString(entry.Message)
	b.WriteByte('\n')
	f.logline(f.startLine, f.current.Id, entry.Message)
	f.startLine++
	f.stepBuffer.Write(b.Bytes())
	return b.Bytes(), nil
}

type ConfigureRunner struct {
	Url             string
	Token           string
	Pat             string
	Labels          []string
	Name            string
	NoDefaultLabels bool
	SystemLabels    []string
	Unattended      bool
	RunnerGroup     string
	Trace           bool
}

type RunnerInstance struct {
	PoolId          int64
	RegistrationUrl string
	Auth            *GitHubAuthResult
	Agent           *TaskAgent
	Key             string
	PKey            *rsa.PrivateKey `json:"-"`
}

type RunnerSettings struct {
	PoolId          int64
	RegistrationUrl string
	Instances       []*RunnerInstance
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

func (config *ConfigureRunner) Configure() int {
	settings := &RunnerSettings{RegistrationUrl: config.Url}
	_ = ReadJson("settings.json", settings)
	instance := &RunnerInstance{}
	settings.Instances = append(settings.Instances, instance)
	if len(config.Url) == 0 {
		if !config.Unattended {
			config.Url = GetInput("Please enter your repository, organization or enterprise url:", "")
		} else {
			fmt.Println("No url provided")
			return 1
		}
	}
	if len(config.Url) == 0 {
		fmt.Println("No url provided")
		return 1
	}
	instance.RegistrationUrl = config.Url
	registerUrl, err := url.Parse(config.Url)
	if err != nil {
		fmt.Printf("Invalid Url: %v\n", config.Url)
		return 1
	}
	apiscope := "/"
	if strings.ToLower(registerUrl.Host) == "github.com" {
		registerUrl.Host = "api." + registerUrl.Host
	} else {
		apiscope = "/api/v3"
	}

	c := &http.Client{}
	if len(config.Token) == 0 {
		if len(config.Pat) > 0 {
			paths := strings.Split(strings.TrimPrefix(registerUrl.Path, "/"), "/")
			url := *registerUrl
			if len(paths) == 1 {
				url.Path = path.Join(apiscope, "orgs", paths[0], "actions/runners/registration-token")
			} else if len(paths) == 2 {
				scope := "repos"
				if strings.EqualFold(paths[0], "enterprises") {
					scope = ""
				}
				url.Path = path.Join(apiscope, scope, paths[0], paths[1], "actions/runners/registration-token")
			} else {
				fmt.Println("Unsupported registration url")
				return 1
			}
			req, _ := http.NewRequest("POST", url.String(), nil)
			req.SetBasicAuth("github", config.Pat)
			req.Header.Add("Accept", "application/vnd.github.v3+json")
			resp, err := c.Do(req)
			if err != nil {
				fmt.Println("Failed to retrive registration token via pat: " + err.Error())
				return 1
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := ioutil.ReadAll(resp.Body)
				fmt.Println("Failed to retrive registration token via pat [" + fmt.Sprint(resp.StatusCode) + "]: " + string(body))
				return 1
			}
			tokenresp := &GitHubRunnerRegisterToken{}
			dec := json.NewDecoder(resp.Body)
			if err := dec.Decode(tokenresp); err != nil {
				fmt.Println("Failed to decode registration token via pat: " + err.Error())
				return 1
			}
			config.Token = tokenresp.Token
		} else {
			if !config.Unattended {
				config.Token = GetInput("Please enter your runner registration token:", "")
			}
		}
	}
	if len(config.Token) == 0 {
		fmt.Println("No runner registration token provided")
		return 1
	}
	registerUrl.Path = path.Join(apiscope, "actions/runner-registration")

	buf := new(bytes.Buffer)
	req := &RunnerAddRemove{}
	req.Url = config.Url
	req.RunnerEvent = "register"
	enc := json.NewEncoder(buf)
	if err := enc.Encode(req); err != nil {
		return 1
	}
	finalregisterUrl := registerUrl.String()
	// fmt.Printf("Try to register runner with url: %v\n", finalregisterUrl)
	r, _ := http.NewRequest("POST", finalregisterUrl, buf)
	r.Header["Authorization"] = []string{"RemoteAuth " + config.Token}
	resp, err := c.Do(r)
	if err != nil {
		fmt.Printf("Failed to register Runner: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Printf("Failed to register Runner with status code: %v\n", resp.StatusCode)
		return 1
	}

	res := &GitHubAuthResult{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(res); err != nil {
		fmt.Printf("error decoding struct from JSON: %v\n", err)
		return 1
	}

	instance.Auth = res
	vssConnection := &VssConnection{
		Client:    c,
		TenantUrl: res.TenantUrl,
		Token:     res.Token,
		Settings:  &RunnerSettings{RegistrationUrl: config.Url},
		Trace:     config.Trace,
	}
	vssConnection.ConnectionData = vssConnection.GetConnectionData()
	{
		taskAgentPool := ""
		taskAgentPools := []string{}
		_taskAgentPools, err := vssConnection.GetAgentPools()
		if err != nil {
			fmt.Printf("Failed to configure runner: %v\n", err)
			return 1
		}
		for _, val := range _taskAgentPools.Value {
			if !val.IsHosted {
				taskAgentPools = append(taskAgentPools, val.Name)
			}
		}
		if len(taskAgentPools) == 0 {
			fmt.Println("Failed to configure runner, no self-hosted runner group available")
			return 1
		}
		if len(config.RunnerGroup) > 0 {
			taskAgentPool = config.RunnerGroup
		} else {
			taskAgentPool = taskAgentPools[0]
			if len(taskAgentPools) > 1 && !config.Unattended {
				taskAgentPool = RunnerGroupSurvey(taskAgentPool, taskAgentPools)
			}
		}
		vssConnection.Settings.PoolId = -1
		for _, val := range _taskAgentPools.Value {
			if !val.IsHosted && strings.EqualFold(val.Name, taskAgentPool) {
				vssConnection.Settings.PoolId = val.Id
			}
		}
		if vssConnection.Settings.PoolId < 0 {
			fmt.Printf("Runner Pool %v not found\n", taskAgentPool)
			return 1
		}
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	instance.Key = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))

	taskAgent := &TaskAgent{}
	taskAgent.Authorization = TaskAgentAuthorization{}
	bs := make([]byte, 4)
	ui := uint32(key.E)
	binary.BigEndian.PutUint32(bs, ui)
	expof := 0
	for ; expof < 3 && bs[expof] == 0; expof++ {
	}
	taskAgent.Authorization.PublicKey = TaskAgentPublicKey{Exponent: base64.StdEncoding.EncodeToString(bs[expof:]), Modulus: base64.StdEncoding.EncodeToString(key.N.Bytes())}
	taskAgent.Version = "3.0.0" //version, will not use fips crypto if set to 0.0.0 *
	taskAgent.OSDescription = "github-act-runner " + runtime.GOOS + "/" + runtime.GOARCH
	if config.Name != "" {
		taskAgent.Name = config.Name
	} else {
		taskAgent.Name = "golang_" + uuid.NewString()
		if !config.Unattended {
			taskAgent.Name = GetInput("Please enter a name of your new runner:", taskAgent.Name)
		}
	}
	if !config.Unattended && len(config.Labels) == 0 {
		if res := GetInput("Please enter custom labels of your new runner (case insensitive, seperated by ','):", ""); len(res) > 0 {
			config.Labels = strings.Split(res, ",")
		}
	}
	systemLabels := make([]string, 0, 3)
	if !config.NoDefaultLabels {
		systemLabels = append(systemLabels, "self-hosted", runtime.GOOS, runtime.GOARCH)
	}
	taskAgent.Labels = make([]AgentLabel, len(systemLabels)+len(config.SystemLabels)+len(config.Labels))
	for i := 0; i < len(systemLabels); i++ {
		taskAgent.Labels[i] = AgentLabel{Name: systemLabels[i], Type: "system"}
	}
	for i := 0; i < len(config.SystemLabels); i++ {
		taskAgent.Labels[i+len(systemLabels)] = AgentLabel{Name: config.SystemLabels[i], Type: "system"}
	}
	for i := 0; i < len(config.Labels); i++ {
		taskAgent.Labels[i+len(systemLabels)+len(config.SystemLabels)] = AgentLabel{Name: config.Labels[i], Type: "user"}
	}
	taskAgent.MaxParallelism = 1
	taskAgent.ProvisioningState = "Provisioned"
	taskAgent.CreatedOn = time.Now().UTC().Format("2006-01-02T15:04:05")
	{
		err := vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "POST", map[string]string{
			"poolId": fmt.Sprint(vssConnection.Settings.PoolId),
		}, map[string]string{}, taskAgent, taskAgent)
		// TODO Replace Runner support
		// {
		// 	poolsreq, _ := http.NewRequest("GET", url, nil)
		// 	AddBearer(poolsreq.Header, res.Token)
		// 	AddContentType(poolsreq.Header, "6.0-preview.2")
		// 	poolsresp, err := c.Do(poolsreq)
		// 	if err != nil {
		// 		fmt.Printf("Failed to create taskAgent: %v\n", err.Error())
		// 		return 1
		// 	} else if poolsresp.StatusCode != 200 {
		// 		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		// 		fmt.Println(string(bytes))
		// 		fmt.Println(buf.String())
		// 		return 1
		// 	} else {
		// 		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		// 		// fmt.Println(string(bytes))
		// 		taskAgent := ""
		// 		taskAgents := []string{}
		// 		// xttr := json.Unmarshal(bytes)
		// 		_taskAgents := &TaskAgents{}
		// 		json.Unmarshal(bytes, _taskAgents)
		// 		for _, val := range _taskAgents.Value {
		// 			taskAgents = append(taskAgents, val.Name)
		// 		}
		// 		prompt := &survey.Select{
		// 			Message: "Choose a runner:",
		// 			Options: taskAgents,
		// 		}
		// 		survey.AskOne(prompt, &taskAgent)
		// 	}
		// }
		if err != nil {
			fmt.Printf("Failed to create taskAgent: %v\n", err.Error())
			return 1
		}
	}
	instance.Agent = taskAgent
	instance.PoolId = vssConnection.Settings.PoolId
	if err := WriteJson("settings.json", settings); err != nil {
		fmt.Printf("Failed to save settings.json: %v\n", err.Error())
	}
	fmt.Println("success")
	return 0
}

type RunRunner struct {
	Once     bool
	Terminal bool
	Trace    bool
}

type JobRun struct {
	RequestId       int64
	JobId           string
	Plan            *TaskOrchestrationPlanReference
	Name            string
	RegistrationUrl string
}

func (taskAgent *TaskAgent) Authorize(c *http.Client, key interface{}) (*VssOAuthTokenResponse, error) {
	tokenresp := &VssOAuthTokenResponse{}
	now := time.Now().UTC().Add(-30 * time.Second)
	token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   taskAgent.Authorization.ClientId,
		Issuer:    taskAgent.Authorization.ClientId,
		Id:        uuid.New().String(),
		Audience:  taskAgent.Authorization.AuthorizationUrl,
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute * 5).Unix(),
	})
	stkn, _ := token2.SignedString(key)

	data := url.Values{}
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", stkn)
	data.Set("grant_type", "client_credentials")

	poolsreq, _ := http.NewRequest("POST", taskAgent.Authorization.AuthorizationUrl, bytes.NewBufferString(data.Encode()))
	poolsreq.Header["Content-Type"] = []string{"application/x-www-form-urlencoded; charset=utf-8"}
	poolsreq.Header["Accept"] = []string{"application/json"}
	poolsresp, err := c.Do(poolsreq)
	if err != nil {
		return nil, errors.New("Failed to Authorize: " + err.Error())
	}
	defer poolsresp.Body.Close()
	if poolsresp.StatusCode != 200 {
		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		return nil, errors.New("Failed to Authorize, service responded with code " + fmt.Sprint(poolsresp.StatusCode) + ": " + string(bytes))
	} else {
		dec := json.NewDecoder(poolsresp.Body)
		if err := dec.Decode(tokenresp); err != nil {
			return nil, err
		}
		return tokenresp, nil
	}
}

func ToStringMap(src interface{}) interface{} {
	bi, ok := src.(map[interface{}]interface{})
	if ok {
		res := make(map[string]interface{})
		for k, v := range bi {
			res[k.(string)] = ToStringMap(v)
		}
		return res
	}
	return src
}

func readLegacyInstance(settings *RunnerSettings, instance *RunnerInstance) int {
	taskAgent := &TaskAgent{}
	var key *rsa.PrivateKey
	req := &GitHubAuthResult{}
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
	instance.PoolId = settings.PoolId
	instance.RegistrationUrl = settings.RegistrationUrl
	instance.Auth = req
	return 0
}

func loadConfiguration() (*RunnerSettings, error) {
	settings := &RunnerSettings{}
	{
		cont, err := ioutil.ReadFile("settings.json")
		if err != nil {
			// Backward compat <= 0.0.3
			// fmt.Printf("The runner needs to be configured first: %v\n", err.Error())
			// return 1
			settings.PoolId = 1
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
		instance := &RunnerInstance{}
		if readLegacyInstance(settings, instance) == 0 {
			settings.Instances = append(settings.Instances, instance)
		}
	}
	return settings, nil
}
func (session *AgentMessageConnection) GetNextMessage(ctx context.Context) (*TaskAgentMessage, error) {
	message := &TaskAgentMessage{}
	for {
		select {
		case <-ctx.Done():
			return nil, context.Canceled
		default:
		}
		err := session.VssConnection.RequestWithContext(ctx, "c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "GET", map[string]string{
			"poolId": fmt.Sprint(session.VssConnection.Settings.PoolId),
		}, map[string]string{
			"sessionId": session.TaskAgentSession.SessionId,
		}, nil, message)
		//TODO lastMessageId=
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			} else if !errors.Is(err, io.EOF) {
				fmt.Printf("Failed to get message, waiting 10 sec before retry: %v\n", err.Error())
				select {
				case <-ctx.Done():
					return nil, context.Canceled
				case <-time.After(10 * time.Second):
				}
			}
		} else {
			return message, nil
		}
	}
}

func (session *AgentMessageConnection) DeleteMessage(message *TaskAgentMessage) error {
	return session.VssConnection.Request("c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "DELETE", map[string]string{
		"poolId":    fmt.Sprint(session.VssConnection.Settings.PoolId),
		"messageId": fmt.Sprint(message.MessageId),
	}, map[string]string{
		"sessionId": session.TaskAgentSession.SessionId,
	}, nil, nil)
}

func (run *RunRunner) Run() int {
	container.SetContainerAllocateTerminal(run.Terminal)
	// trap Ctrl+C
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())
	firstJobReceived := false
	jobctx, cancelJob := context.WithCancel(context.Background())
	cancelJob()
	go func() {
		<-channel
		select {
		case <-jobctx.Done():
			fmt.Println("CTRL+C received, no job is running shutdown")
			cancel()
		default:
			fmt.Println("CTRL+C received, stop accepting new jobs and exit after the current job finishs")
			// Switch to run once mode
			run.Once = true
			firstJobReceived = true
		}
		for {
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
		<-jobctx.Done()
	}()
	settings, err := loadConfiguration()
	if err != nil {
		fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
		return 1
	}
	for {
		var sessions []*TaskAgentSession
		mu := &sync.Mutex{}
		joblisteningctx, cancelJobListening := context.WithCancel(ctx)
		defer cancelJobListening()
		wg := new(sync.WaitGroup)
		wg.Add(len(settings.Instances))
		for _, instance := range settings.Instances {
			go func(instance *RunnerInstance) int {
				defer wg.Done()
				vssConnection := &VssConnection{
					Client: &http.Client{Transport: &http.Transport{
						MaxIdleConns:    1,
						IdleConnTimeout: 100 * time.Second,
					}},
					TenantUrl: instance.Auth.TenantUrl,
					Settings: &RunnerSettings{
						PoolId:          instance.PoolId,
						RegistrationUrl: instance.RegistrationUrl,
					},
					TaskAgent: instance.Agent,
					Key:       instance.PKey,
					Trace:     run.Trace,
				}
				vssConnection.ConnectionData = vssConnection.GetConnectionData()
				jobrun := &JobRun{}
				if ReadJson("jobrun.json", jobrun) == nil && ((jobrun.RegistrationUrl == instance.RegistrationUrl && jobrun.Name == instance.Agent.Name) || (len(settings.Instances) == 1)) {
					result := "Failed"
					finish := &JobEvent{
						Name:      "JobCompleted",
						JobId:     jobrun.JobId,
						RequestId: jobrun.RequestId,
						Result:    result,
					}
					go func() {
						for i := 0; ; i++ {
							if err := vssConnection.FinishJob(finish, jobrun); err != nil {
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
				var session *AgentMessageConnection
				defer func() {
					if session != nil {
						if err := session.Delete(); err != nil {
							fmt.Printf("WARNING: Failed to delete active session: %v\n", err)
						} else {
							mu.Lock()
							for i, _session := range sessions {
								if session.TaskAgentSession == _session {
									sessions[i] = sessions[len(sessions)-1]
									sessions = sessions[:len(sessions)-1]
								}
							}
							WriteJson("sessions.json", sessions)
							mu.Unlock()
						}
					}
				}()
				xctx, _c := context.WithCancel(joblisteningctx)
				defer _c()
				for {
					message := &TaskAgentMessage{}
					success := false
					for !success {
						select {
						case <-joblisteningctx.Done():
							return 0
						default:
						}
						if session == nil {
							session2, err := vssConnection.CreateSession()
							if err != nil {
								fmt.Printf("Failed to recreate Session, waiting 30 sec before retry: %v\n", err.Error())
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
									fmt.Println("Listening for Jobs")
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
							"poolId": fmt.Sprint(instance.PoolId),
						}, map[string]string{
							"sessionId": session.TaskAgentSession.SessionId,
						}, nil, message)
						//TODO lastMessageId=
						if err != nil {
							if errors.Is(err, context.Canceled) {
								return 0
							} else if !errors.Is(err, io.EOF) {
								fmt.Printf("Failed to get message, waiting 10 sec before retry: %v\n", err.Error())
								select {
								case <-ctx.Done():
									fmt.Println("Canceled stopping")
									return 0
								case <-time.After(10 * time.Second):
								}
							}
						} else {
							if firstJobReceived && strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") {
								// It seems run once isn't supported by the backend, do the same as the official runner
								// Skip deleting the job message and cancel earlier
								fmt.Println("Received a second job, but running in run once mode abort")
								return 1
							}
							success = true
							err := vssConnection.Request("c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "DELETE", map[string]string{
								"poolId":    fmt.Sprint(instance.PoolId),
								"messageId": fmt.Sprint(message.MessageId),
							}, map[string]string{
								"sessionId": session.TaskAgentSession.SessionId,
							}, nil, nil)
							if err != nil {
								fmt.Println("Failed to delete Message")
								success = false
							}
						}
					}
					if success {
						if strings.EqualFold(message.MessageType, "JobCancellation") && cancelJob != nil {
							cancelJob()
						} else if strings.EqualFold(message.MessageType, "PipelineAgentJobRequest") {
							if run.Once {
								fmt.Println("First job received")
								firstJobReceived = true
							}
							var finishJob context.CancelFunc
							jobctx, finishJob = context.WithCancel(context.Background())
							var jobExecCtx context.Context
							jobExecCtx, cancelJob = context.WithCancel(context.Background())
							runJob(vssConnection, run, cancel, cancelJob, finishJob, jobExecCtx, jobctx, session, *message, instance)
							{
								cancelJobListening()
								for {
									message, err := session.GetNextMessage(jobExecCtx)
									if errors.Is(err, context.Canceled) {
										break
									} else if strings.EqualFold(message.MessageType, "JobCancellation") && cancelJob != nil {
										cancelJob()
									}
									session.DeleteMessage(message)
								}
							}
						} else {
							fmt.Println("Ignoring incoming message of type: " + message.MessageType)
						}
					}
				}
			}(instance)
		}
		<-joblisteningctx.Done()
		<-jobctx.Done()
		wg.Wait()
		if run.Once {
			return 0
		}
	}
}

func runJob(vssConnection *VssConnection, run *RunRunner, cancel context.CancelFunc, cancelJob context.CancelFunc, finishJob context.CancelFunc, jobExecCtx context.Context, jobctx context.Context, session *AgentMessageConnection, message TaskAgentMessage, instance *RunnerInstance) {
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
		iv, _ := base64.StdEncoding.DecodeString(message.IV)
		src, _ := base64.StdEncoding.DecodeString(message.Body)
		cbcdec := cipher.NewCBCDecrypter(session.Block, iv)
		cbcdec.CryptBlocks(src, src)
		maxlen := session.Block.BlockSize()
		validlen := len(src)
		if int(src[len(src)-1]) < maxlen {
			ok := true
			for i := 2; i <= int(src[len(src)-1]); i++ {
				if src[len(src)-i] != src[len(src)-1] {
					ok = false
					break
				}
			}
			if ok {
				validlen -= int(src[len(src)-1])
			}
		}
		off := 0
		// skip utf8 bom, c# cryptostream uses it for utf8
		if src[0] == 239 && src[1] == 187 && src[2] == 191 {
			off = 3
		}
		jobreq := &AgentJobRequestMessage{}
		{
			dec := json.NewDecoder(bytes.NewReader(src[off:validlen]))
			dec.Decode(jobreq)
		}
		jobrun := &JobRun{
			RequestId:       jobreq.RequestId,
			JobId:           jobreq.JobId,
			Plan:            jobreq.Plan,
			RegistrationUrl: instance.RegistrationUrl,
			Name:            instance.Agent.Name,
		}
		{
			if err := WriteJson("jobrun.json", jobrun); err != nil {
				fmt.Printf("INFO: Failed to create jobrun.json: %v\n", err)
			}
		}
		fmt.Printf("Running Job '%v'\n", jobreq.JobDisplayName)
		finishJob2 := func(result string, outputs *map[string]VariableValue) {
			finish := &JobEvent{
				Name:      "JobCompleted",
				JobId:     jobreq.JobId,
				RequestId: jobreq.RequestId,
				Result:    result,
				Outputs:   outputs,
			}
			for i := 0; ; i++ {
				if err := vssConnection.FinishJob(finish, jobrun); err != nil {
					fmt.Printf("Failed to finish Job '%v' with Status %v: %v\n", jobreq.JobDisplayName, result, err.Error())
				} else {
					fmt.Printf("Finished Job '%v' with Status %v\n", jobreq.JobDisplayName, result)
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
		wrap := &TimelineRecordWrapper{}
		wrap.Count = 2
		wrap.Value = make([]TimelineRecord, wrap.Count)
		wrap.Value[0] = CreateTimelineEntry("", rqt.JobName, rqt.JobDisplayName)
		wrap.Value[0].Id = rqt.JobId
		wrap.Value[0].Type = "Job"
		wrap.Value[0].Order = 0
		wrap.Value[0].Start()
		wrap.Value[1] = CreateTimelineEntry(rqt.JobId, "__setup", "Setup Job")
		wrap.Value[1].Order = 1
		wrap.Value[1].Start()
		vssConnection.UpdateTimeLine(jobreq.Timeline.Id, jobreq, wrap)
		failInitJob := func(message string) {
			wrap.Value[1].Log = &TaskLogReference{Id: vssConnection.UploadLogFile(jobreq.Timeline.Id, jobreq, message)}
			wrap.Value[1].Complete("Failed")
			wrap.Value[0].Complete("Failed")
			vssConnection.UpdateTimeLine(jobreq.Timeline.Id, jobreq, wrap)
			fmt.Println(message)
			finishJob("Failed")
		}
		defer func() {
			if err := recover(); err != nil {
				failInitJob("The worker panicked with message: " + fmt.Sprint(err) + "\n" + string(debug.Stack()))
			}
		}()
		con := *vssConnection
		go func() {
			for {
				err := con.Request("fc825784-c92a-4299-9221-998a02d1b54f", "5.1-preview", "PATCH", map[string]string{
					"poolId":    fmt.Sprint(instance.PoolId),
					"requestId": fmt.Sprint(jobreq.RequestId),
				}, map[string]string{
					"lockToken": "00000000-0000-0000-0000-000000000000",
				}, &RenewAgent{RequestId: jobreq.RequestId}, nil)
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
		if jobreq.Resources == nil {
			failInitJob("Missing Job Resources")
			return
		}
		if jobreq.Resources.Endpoints == nil {
			failInitJob("Missing Job Resources Endpoints")
			return
		}
		// orchid := ""
		cacheUrl := ""
		for _, endpoint := range jobreq.Resources.Endpoints {
			if strings.EqualFold(endpoint.Name, "SystemVssConnection") && endpoint.Authorization.Parameters != nil && endpoint.Authorization.Parameters["AccessToken"] != "" {
				jobToken := endpoint.Authorization.Parameters["AccessToken"]
				jobTenant := endpoint.Url
				claims := jwt.MapClaims{}
				jwt.ParseWithClaims(jobToken, claims, func(t *jwt.Token) (interface{}, error) {
					return nil, nil
				})
				// if _orchid, suc := claims["orchid"]; suc {
				// 	orchid = _orchid.(string)
				// }
				_cacheUrl, ok := endpoint.Data["CacheServerUrl"]
				if ok {
					cacheUrl = _cacheUrl
				}
				vssConnection = &VssConnection{
					Client:    vssConnection.Client,
					TenantUrl: jobTenant,
					Token:     jobToken,
					Trace:     run.Trace,
				}
				vssConnection.ConnectionData = vssConnection.GetConnectionData()
			}
		}

		rawGithubCtx, ok := rqt.ContextData["github"]
		if !ok {
			fmt.Println("missing github context in ContextData")
			finishJob("Failed")
			return
		}
		githubCtx := rawGithubCtx.ToRawObject()
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
		matrix := make(map[string]interface{})
		if rawMatrix, ok := rqt.ContextData["matrix"]; ok {
			rawobj := rawMatrix.ToRawObject()
			if tmpmatrix, ok := rawobj.(map[string]interface{}); ok {
				matrix = tmpmatrix
			} else if rawobj != nil {
				failInitJob("matrix: not a map")
				return
			}
		}
		env := make(map[string]string)
		if rqt.EnvironmentVariables != nil {
			for _, rawenv := range rqt.EnvironmentVariables {
				if tmpenv, ok := rawenv.ToRawObject().(map[interface{}]interface{}); ok {
					for k, v := range tmpenv {
						key, ok := k.(string)
						if !ok {
							failInitJob("env key: act doesn't support non strings")
							return
						}
						value, ok := v.(string)
						if !ok {
							failInitJob("env value: act doesn't support non strings")
							return
						}
						env[key] = value
					}
				} else {
					failInitJob("env: not a map")
					return
				}
			}
		}
		env["ACTIONS_RUNTIME_URL"] = vssConnection.TenantUrl
		env["ACTIONS_RUNTIME_TOKEN"] = vssConnection.Token
		if len(cacheUrl) > 0 {
			env["ACTIONS_CACHE_URL"] = cacheUrl
		}

		defaults := model.Defaults{}
		if rqt.Defaults != nil {
			for _, rawenv := range rqt.Defaults {
				rawobj := rawenv.ToRawObject()
				rawobj = ToStringMap(rawobj)
				b, err := json.Marshal(rawobj)
				if err != nil {
					failInitJob("Failed to eval defaults")
					return
				}
				json.Unmarshal(b, &defaults)
			}
		}
		steps := []*model.Step{}
		for _, step := range rqt.Steps {
			st := strings.ToLower(step.Reference.Type)
			inputs := make(map[interface{}]interface{})
			if step.Inputs != nil {
				if tmpinputs, ok := step.Inputs.ToRawObject().(map[interface{}]interface{}); ok {
					inputs = tmpinputs
				} else {
					failInitJob("step.Inputs: not a map")
					return
				}
			}

			env := &yaml.Node{}
			if step.Environment != nil {
				env = step.Environment.ToYamlNode()
			}

			continueOnError := false
			if step.ContinueOnError != nil {
				tmpcontinueOnError, ok := step.ContinueOnError.ToRawObject().(bool)
				if !ok {
					failInitJob("ContinueOnError: act doesn't support expressions here")
					return
				}
				continueOnError = tmpcontinueOnError
			}
			var timeoutMinutes int64 = 0
			if step.TimeoutInMinutes != nil {
				rawTimeout, ok := step.TimeoutInMinutes.ToRawObject().(float64)
				if !ok {
					failInitJob("TimeoutInMinutes: act doesn't support expressions here")
					return
				}
				timeoutMinutes = int64(rawTimeout)
			}
			var displayName string = ""
			if step.DisplayNameToken != nil {
				rawDisplayName, ok := step.DisplayNameToken.ToRawObject().(string)
				if !ok {
					failInitJob("DisplayNameToken: act doesn't support no strings")
					return
				}
				displayName = rawDisplayName
			}
			if step.ContextName == "" {
				step.ContextName = "___" + uuid.New().String()
			}

			switch st {
			case "script":
				rawwd, haswd := inputs["workingDirectory"]
				var wd string
				if haswd {
					tmpwd, ok := rawwd.(string)
					if !ok {
						failInitJob("workingDirectory: act doesn't support non strings")
						return
					}
					wd = tmpwd
				} else {
					wd = ""
				}
				rawshell, hasshell := inputs["shell"]
				shell := ""
				if hasshell {
					sshell, ok := rawshell.(string)
					if ok {
						shell = sshell
					} else {
						failInitJob("shell is not a string")
						return
					}
				}
				scriptContent, ok := inputs["script"].(string)
				if ok {
					steps = append(steps, &model.Step{
						ID:               step.ContextName,
						If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
						Name:             displayName,
						Run:              scriptContent,
						WorkingDirectory: wd,
						Shell:            shell,
						ContinueOnError:  continueOnError,
						TimeoutMinutes:   timeoutMinutes,
						Env:              *env,
					})
				} else {
					failInitJob("Missing script")
					return
				}
			case "containerregistry", "repository":
				uses := ""
				if st == "containerregistry" {
					uses = "docker://" + step.Reference.Image
				} else if strings.ToLower(step.Reference.RepositoryType) == "self" {
					uses = step.Reference.Path
				} else {
					uses = step.Reference.Name
					if len(step.Reference.Path) > 0 {
						uses = uses + "/" + step.Reference.Path
					}
					uses = uses + "@" + step.Reference.Ref
				}
				with := map[string]string{}
				for k, v := range inputs {
					k, ok := k.(string)
					if !ok {
						failInitJob("with input key is not a string")
						return
					}
					val, ok := v.(string)
					if !ok {
						failInitJob("with input value is not a string")
						return
					}
					with[k] = val
				}

				steps = append(steps, &model.Step{
					ID:               step.ContextName,
					If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
					Name:             displayName,
					Uses:             uses,
					WorkingDirectory: "",
					With:             with,
					ContinueOnError:  continueOnError,
					TimeoutMinutes:   timeoutMinutes,
					Env:              *env,
				})
			}
		}
		rawContainer := yaml.Node{}
		if rqt.JobContainer != nil {
			rawContainer = *rqt.JobContainer.ToYamlNode()
			// Fake step to catch the post log
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
		services := make(map[string]*model.ContainerSpec)
		if rqt.JobServiceContainers != nil {
			rawServiceContainer, ok := rqt.JobServiceContainers.ToRawObject().(map[interface{}]interface{})
			if !ok {
				failInitJob("Job service container is not nil, but also not a map")
				return
			}
			for name, rawcontainer := range rawServiceContainer {
				containerName, ok := name.(string)
				if !ok {
					failInitJob("containername is not a string")
					return
				}
				spec := &model.ContainerSpec{}
				b, err := json.Marshal(ToStringMap(rawcontainer))
				if err != nil {
					failInitJob("Failed to serialize ContainerSpec")
					return
				}
				err = json.Unmarshal(b, &spec)
				if err != nil {
					failInitJob("Failed to deserialize ContainerSpec")
					return
				}
				services[containerName] = spec
			}
		}
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
		rc := &runner.RunContext{
			Name: uuid.New().String(),
			Config: &runner.Config{
				Workdir: ".",
				Secrets: secrets,
				Platforms: map[string]string{
					"dummy": "-self-hosted",
				},
				LogOutput:           true,
				EventName:           githubCtxMap["event_name"].(string),
				GitHubInstance:      githubCtxMap["server_url"].(string)[8:],
				ForceRemoteCheckout: true, // Needed to avoid copy the non exiting working dir
				ReuseContainers:     false,
				CompositeRestrictions: &model.CompositeRestrictions{
					AllowCompositeUses:            true,
					AllowCompositeIf:              true,
					AllowCompositeContinueOnError: true,
				},
			},
			Env: env,
			Run: &model.Run{
				JobID: rqt.JobId,
				Workflow: &model.Workflow{
					Name:     githubCtxMap["workflow"].(string),
					Defaults: defaults,
					Jobs: map[string]*model.Job{
						rqt.JobId: {
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

		// Prepare act to fill previous job outputs
		if rawNeedstx, ok := rqt.ContextData["needs"]; ok {
			needsCtx := rawNeedstx.ToRawObject()
			if needsCtxMap, ok := needsCtx.(map[string]interface{}); ok {
				a := make([]*yaml.Node, 0)
				for k, v := range needsCtxMap {
					a = append(a, &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: k})
					outputs := make(map[string]string)
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
					}
					rc.Run.Workflow.Jobs[k] = &model.Job{
						Outputs: outputs,
					}
				}
				rc.Run.Workflow.Jobs[rqt.JobId].RawNeeds = yaml.Node{Kind: yaml.SequenceNode, Content: a}
			}
		}
		// Prepare act to add job outputs to current job
		if rqt.JobOutputs != nil {
			o := rqt.JobOutputs.ToRawObject()
			if m, ok := o.(map[interface{}]interface{}); ok {
				for k, v := range m {
					if kv, ok := k.(string); ok {
						if sv, ok := v.(string); ok {
							rc.Run.Workflow.Jobs[rqt.JobId].Outputs[kv] = sv
						}
					}
				}
			}
		}

		val, _ := json.Marshal(githubCtx)
		sv := string(val)
		rc.GithubContextBase = &sv
		rc.JobName = "beta"

		ee := rc.NewExpressionEvaluator()
		rc.ExprEval = ee
		logger := logrus.New()

		formatter := new(ghaFormatter)
		formatter.rc = rc
		formatter.rqt = rqt
		formatter.stepBuffer = &bytes.Buffer{}

		logger.SetFormatter(formatter)
		logger.SetOutput(io.MultiWriter())
		level := logrus.InfoLevel
		if sd, ok := rqt.Variables["ACTIONS_STEP_DEBUG"]; !ok || sd.Value == "true" || sd.Value == "1" {
			level = logrus.DebugLevel
		}
		logger.SetLevel(level)
		logrus.SetLevel(level)
		logrus.SetFormatter(formatter)
		logrus.SetOutput(io.MultiWriter())

		rc.CurrentStep = "__setup"
		rc.InitStepResults([]string{rc.CurrentStep})

		for i := 0; i < len(steps); i++ {
			wrap.Value = append(wrap.Value, CreateTimelineEntry(rqt.JobId, steps[i].ID, steps[i].String()))
			wrap.Value[i+2].Order = int32(i + 2)
		}
		formatter.current = &wrap.Value[1]
		wrap.Count = int64(len(wrap.Value))
		vssConnection.UpdateTimeLine(jobreq.Timeline.Id, jobreq, wrap)
		{
			formatter.updateTimeLine = func() {
				vssConnection.UpdateTimeLine(jobreq.Timeline.Id, jobreq, wrap)
			}
			formatter.uploadLogFile = func(log string) int {
				return vssConnection.UploadLogFile(jobreq.Timeline.Id, jobreq, log)
			}
		}
		var outputMap *map[string]VariableValue
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
				logchan := make(chan *TimelineRecordFeedLinesWrapper, 64)
				formatter.logline = func(startLine int64, recordId string, line string) {
					lines := &TimelineRecordFeedLinesWrapper{}
					lines.Count = 1
					lines.StartLine = &startLine
					lines.StepId = recordId
					lines.Value = []string{line}
					logchan <- lines
				}
				go func() {
					defer cancelLog()
					sendLog := func(lines *TimelineRecordFeedLinesWrapper) {
						err := vssConnection.Request("858983e4-19bd-4c5e-864c-507b59b58b12", "5.1-preview", "POST", map[string]string{
							"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
							"planId":          jobreq.Plan.PlanId,
							"hubName":         jobreq.Plan.PlanType,
							"timelineId":      jobreq.Timeline.Id,
							"recordId":        lines.StepId,
						}, map[string]string{}, lines, nil)

						if err != nil {
							fmt.Println("Failed to upload logline: " + err.Error())
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
									if line.StepId == lines.StepId {
										lines.Count++
										lines.Value = append(lines.Value, line.Value[0])
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

			logger.Log(logrus.DebugLevel, "Runner Name: "+instance.Agent.Name)
			logger.Log(logrus.DebugLevel, "Runner OSDescription: github-act-runner "+runtime.GOOS+"/"+runtime.GOARCH)
			logger.Log(logrus.DebugLevel, "Runner Version: "+version)
			rc.Executor()(common.WithLogger(jobExecCtx, logger))

			// Prepare results for github server
			if rqt.JobOutputs != nil {
				m := make(map[string]VariableValue)
				outputMap = &m
				for k, v := range rc.Run.Workflow.Jobs[rqt.JobId].Outputs {
					m[k] = VariableValue{Value: v}
				}
			}

			for _, stepStatus := range rc.StepResults {
				if !stepStatus.Success {
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
					} else if f.rc.StepResults[f.current.RefName].Success {
						f.current.Complete("Succeeded")
					} else {
						f.current.Complete("Failed")
					}
					if f.stepBuffer.Len() > 0 {
						f.current.Log = &TaskLogReference{Id: f.uploadLogFile(f.stepBuffer.String())}
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
			if vssConnection.UpdateTimeLine(jobreq.Timeline.Id, jobreq, wrap) != nil && i < 10 {
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

type RemoveRunner struct {
	Url        string
	Name       string
	Token      string
	Pat        string
	Unattended bool
	Trace      bool
	Force      bool
}

func (config *RemoveRunner) Remove() int {
	c := &http.Client{}
	settings, err := loadConfiguration()
	if err != nil {
		fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
		return 1
	}
	defer func() {
		os.Remove("agent.json")
		os.Remove("auth.json")
		os.Remove("cred.pkcs1")
		WriteJson("settings.json", settings)
	}()
	var instancesToRemove []*RunnerInstance
	for _, i := range settings.Instances {
		if (len(config.Url) == 0 || i.RegistrationUrl == config.Url) || (len(config.Name) == 0 || i.Agent.Name == config.Name) {
			instancesToRemove = append(instancesToRemove, i)
		}
	}
	if len(instancesToRemove) == 0 {
		fmt.Println("Nothing to do, no runner matches")
		return 0
	}
	if !config.Unattended && len(instancesToRemove) > 1 {
		options := make([]string, len(instancesToRemove))
		for i, instance := range instancesToRemove {
			options[i] = fmt.Sprintf("%v (%v)", instance.Agent.Name, instance.RegistrationUrl)
		}
		result := GetMultiSelectInput("Please select the instances to remove, use --unattended to remove all", options)
		var instancesToRemoveFiltered []*RunnerInstance
		for _, res := range result {
			for i := 0; i < len(options); i++ {
				if options[i] == res {
					instancesToRemoveFiltered = append(instancesToRemoveFiltered, instancesToRemove[i])
				}
			}
		}
		instancesToRemove = instancesToRemoveFiltered
		if len(instancesToRemove) == 0 {
			fmt.Println("Nothing selected, no runner matches")
			return 0
		}
	}
	regurl := ""
	needsPat := false
	for _, i := range instancesToRemove {
		if len(regurl) > 0 && regurl != i.RegistrationUrl {
			needsPat = true
		} else {
			regurl = i.RegistrationUrl
		}
	}
	if needsPat && len(config.Pat) == 0 {
		if !config.Unattended {
			config.Pat = GetInput("Please enter your Personal Access token", "")
		}
		if len(config.Pat) == 0 {
			fmt.Println("You have to provide a Personal access token with access to the repositories to remove or use the --url parameter")
			return 1
		}
	}
	for _, instance := range instancesToRemove {
		result := func() int {
			res := &GitHubAuthResult{}
			{
				buf := new(bytes.Buffer)
				req := &RunnerAddRemove{}
				req.Url = instance.RegistrationUrl
				req.RunnerEvent = "remove"
				enc := json.NewEncoder(buf)
				if err := enc.Encode(req); err != nil {
					return 1
				}
				registerUrl, err := url.Parse(instance.RegistrationUrl)
				if err != nil {
					fmt.Printf("Invalid Url: %v\n", instance.RegistrationUrl)
					return 1
				}
				apiscope := "/"
				if strings.ToLower(registerUrl.Host) == "github.com" {
					registerUrl.Host = "api." + registerUrl.Host
				} else {
					apiscope = "/api/v3"
				}

				c := &http.Client{}
				if len(config.Token) == 0 || needsPat {
					if len(config.Pat) > 0 {
						paths := strings.Split(strings.TrimPrefix(registerUrl.Path, "/"), "/")
						url := *registerUrl
						if len(paths) == 1 {
							url.Path = path.Join(apiscope, "orgs", paths[0], "actions/runners/remove-token")
						} else if len(paths) == 2 {
							scope := "repos"
							if strings.EqualFold(paths[0], "enterprises") {
								scope = ""
							}
							url.Path = path.Join(apiscope, scope, paths[0], paths[1], "actions/runners/remove-token")
						} else {
							fmt.Println("Unsupported remove url")
							return 1
						}
						req, _ := http.NewRequest("POST", url.String(), nil)
						req.SetBasicAuth("github", config.Pat)
						req.Header.Add("Accept", "application/vnd.github.v3+json")
						resp, err := c.Do(req)
						if err != nil {
							fmt.Println("Failed to retrive remove token via pat: " + err.Error())
							return 1
						}
						defer resp.Body.Close()
						if resp.StatusCode < 200 || resp.StatusCode >= 300 {
							body, _ := ioutil.ReadAll(resp.Body)
							fmt.Println("Failed to retrive remove token via pat [" + fmt.Sprint(resp.StatusCode) + "]: " + string(body))
							return 1
						}
						tokenresp := &GitHubRunnerRegisterToken{}
						dec := json.NewDecoder(resp.Body)
						if err := dec.Decode(tokenresp); err != nil {
							fmt.Println("Failed to decode remove token via pat: " + err.Error())
							return 1
						}
						config.Token = tokenresp.Token
					} else {
						if !config.Unattended {
							config.Token = GetInput("Please enter your runner remove token:", "")
						}
					}
				}
				if len(config.Token) == 0 {
					fmt.Println("No runner remove token provided")
					return 1
				}
				registerUrl.Path = path.Join(apiscope, "actions/runner-registration")
				finalregisterUrl := registerUrl.String()
				//fmt.Printf("Try to remove runner with url: %v\n", finalregisterUrl)
				r, _ := http.NewRequest("POST", finalregisterUrl, buf)
				r.Header["Authorization"] = []string{"RemoteAuth " + config.Token}
				resp, err := c.Do(r)
				if err != nil {
					fmt.Printf("Failed to remove Runner: %v\n", err)
					return 1
				}
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					fmt.Printf("Failed to remove Runner with status code: %v\n", resp.StatusCode)
					return 1
				}

				dec := json.NewDecoder(resp.Body)
				if err := dec.Decode(res); err != nil {
					fmt.Printf("Failed to remove Runner:\nerror decoding struct from JSON: %v\n", err)
					return 1
				}
			}

			vssConnection := &VssConnection{
				Client:    c,
				TenantUrl: res.TenantUrl,
				Token:     res.Token,
				Settings: &RunnerSettings{
					PoolId:          instance.PoolId,
					RegistrationUrl: instance.RegistrationUrl,
				},
				Trace: config.Trace,
			}
			vssConnection.ConnectionData = vssConnection.GetConnectionData()
			if err := vssConnection.DeleteAgent(instance.Agent); err != nil {
				fmt.Printf("Failed to remove Runner from server: %v\n", err)
				return 1
			}
			return 0
		}()
		if result != 0 && !config.Force {
			return result
		}
		for i := range settings.Instances {
			if settings.Instances[i] == instance {
				settings.Instances[i] = settings.Instances[len(settings.Instances)-1]
				settings.Instances = settings.Instances[:len(settings.Instances)-1]
				break
			}
		}
	}
	fmt.Println("success")
	return 0
}

var version string = "0.0.0"

func main() {
	config := &ConfigureRunner{}
	run := &RunRunner{}
	remove := &RemoveRunner{}
	var cmdConfigure = &cobra.Command{
		Use:   "configure",
		Short: "Configure your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(config.Configure())
		},
	}

	cmdConfigure.Flags().StringVar(&config.Url, "url", "", "url of your repository, organization or enterprise")
	cmdConfigure.Flags().StringVar(&config.Token, "token", "", "runner registration token")
	cmdConfigure.Flags().StringVar(&config.Pat, "pat", "", "personal access token with access to your repository, organization or enterprise")
	cmdConfigure.Flags().StringSliceVarP(&config.Labels, "labels", "l", []string{}, "custom user labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Name, "name", "", "custom runner name")
	cmdConfigure.Flags().BoolVar(&config.NoDefaultLabels, "no-default-labels", false, "do not automatically add the following system labels: self-hosted, "+runtime.GOOS+" and "+runtime.GOARCH)
	cmdConfigure.Flags().StringSliceVarP(&config.SystemLabels, "system-labels", "", []string{}, "custom system labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Token, "runnergroup", "", "name of the runner group to use will ask if more than one is available")
	cmdConfigure.Flags().BoolVar(&config.Unattended, "unattended", false, "suppress shell prompts during configure")
	cmdConfigure.Flags().BoolVar(&config.Trace, "trace", false, "trace http communication with the github action service")
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
			os.Exit(remove.Remove())
		},
	}

	cmdRemove.Flags().StringVar(&remove.Url, "url", "", "url of your repository, organization or enterprise ( required to unconfigure version <= 0.0.3 )")
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
