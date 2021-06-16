package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/nektos/act/pkg/common"
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
	Id         string
	Scope      string
	PoolType   int
	Name       string
	IsHosted   bool
	IsInternal bool
	Size       int
}

type TaskAgentPool struct {
	TaskAgentPoolReference
}

type TaskAgentPublicKey struct {
	Exponent string
	Modulus  string
}

type TaskAgentAuthorization struct {
	AuthorizationUrl string `json:"authorizationUrl,omitempty"`
	ClientId         string `json:"clientId,omitempty"`
	PublicKey        TaskAgentPublicKey
}

type AgentLabel struct {
	Id   int
	Name string
	Type string
}

type TaskAgent struct {
	Authorization  TaskAgentAuthorization
	Labels         []AgentLabel
	MaxParallelism int
	Id             int
	Name           string
	Version        string
	OSDescription  string
	// Enabled           bool
	Status            int
	ProvisioningState string
	// AccessPoint       string
	CreatedOn string
}

type TaskLogReference struct {
	Id       int
	Location *string
}

type TaskLog struct {
	TaskLogReference
	IndexLocation *string `json:"IndexLocation,omitempty"`
	Path          *string `json:"Path,omitempty"`
	LineCount     *int64  `json:"LineCount,omitempty"`
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
	Clean *string `json:"Clean,omitempty"`
}

type MaskHint struct {
	Type  string
	Value string
}

type ActionsEnvironmentReference struct {
	Name *string `json:"Name,omitempty"`
	Url  *string `json:"Url,omitempty"`
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
	SessionId         string `json:"sessionId,omitempty"`
	EncryptionKey     TaskAgentSessionKey
	OwnerName         string
	Agent             TaskAgent
	UseFipsEncryption bool
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
	Outputs            *map[string]VariableValue    `json:"Outputs,omitempty"`
	ActionsEnvironment *ActionsEnvironmentReference `json:"ActionsEnvironment,omitempty"`
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

func GetConnectionData(c *http.Client, tenantUrl string) *ConnectionData {
	_url, _ := url.Parse(tenantUrl)
	_url.Path = path.Join(_url.Path, "_apis/connectionData")
	q := _url.Query()
	q.Add("connectOptions", "1")
	q.Add("lastChangeId", "-1")
	q.Add("lastChangeId64", "-1")
	_url.RawQuery = q.Encode()
	connectionData, _ := http.NewRequest("GET", _url.String(), nil)
	connectionDataResp, _ := c.Do(connectionData)
	connectionData_ := &ConnectionData{}

	dec2 := json.NewDecoder(connectionDataResp.Body)
	dec2.Decode(connectionData_)
	return connectionData_
}

func BuildUrl(tenantUrl string, relativePath string, ppath map[string]string, query map[string]string) string {
	url2, _ := url.Parse(tenantUrl)
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

func (taskAgent *TaskAgent) CreateSession(connectionData_ *ConnectionData, c *http.Client, tenantUrl string, key *rsa.PrivateKey, token string) (*TaskAgentSession, cipher.Block) {
	session := &TaskAgentSession{}
	session.Agent = *taskAgent
	session.UseFipsEncryption = true
	session.OwnerName = "RUNNER"
	serv := connectionData_.GetServiceDefinition("134e239e-2df3-4794-a6f6-24f1f19ec8dc")
	url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
		"area":     serv.ServiceType,
		"resource": serv.DisplayName,
		"poolId":   fmt.Sprint(1),
	}, map[string]string{})
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.Encode(session)

	poolsreq, _ := http.NewRequest("POST", url, buf)
	poolsreq.Header["Authorization"] = []string{"bearer " + token}
	AddContentType(poolsreq.Header, "6.0-preview")
	AddHeaders(poolsreq.Header)
	poolsresp, _ := c.Do(poolsreq)

	dec := json.NewDecoder(poolsresp.Body)
	dec.Decode(session)
	d, _ := base64.StdEncoding.DecodeString(session.EncryptionKey.Value)
	sessionKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, d, []byte{})
	if sessionKey == nil {
		return nil, nil
	}
	b, _ := aes.NewCipher(sessionKey)
	return session, b
}

func (session *TaskAgentSession) Delete(connectionData_ *ConnectionData, c *http.Client, tenantUrl string, token string) error {
	serv := connectionData_.GetServiceDefinition("134e239e-2df3-4794-a6f6-24f1f19ec8dc")
	url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
		"area":      serv.ServiceType,
		"resource":  serv.DisplayName,
		"poolId":    fmt.Sprint(1),
		"sessionId": session.SessionId,
	}, map[string]string{})

	poolsreq, _ := http.NewRequest("DELETE", url, nil)
	poolsreq.Header["Authorization"] = []string{"bearer " + token}
	AddContentType(poolsreq.Header, "6.0-preview")
	AddHeaders(poolsreq.Header)
	poolsresp, _ := c.Do(poolsreq)
	if poolsresp.StatusCode != 200 {
		return errors.New("failed to delete session")
	}
	return nil
}

func AddHeaders(header http.Header) {
	header["X-VSS-E2EID"] = []string{"7f1c293d-97ce-4c59-9e4b-0677c85b8144"}
	header["X-TFS-FedAuthRedirect"] = []string{"Suppress"}
	header["X-TFS-Session"] = []string{"0a6ba747-926b-4ba3-a852-00ab5b5b071a"}
}

func AddContentType(header http.Header, apiversion string) {
	header["Content-Type"] = []string{"application/json; charset=utf-8; api-version=" + apiversion}
	header["Accept"] = []string{"application/json; api-version=" + apiversion}
}

func AddBearer(header http.Header, token string) {
	header["Authorization"] = []string{"bearer " + token}
}

func UpdateTimeLine(con *ConnectionData, c *http.Client, tenantUrl string, timelineId string, jobreq *AgentJobRequestMessage, wrap *TimelineRecordWrapper, token string) {
	serv := con.GetServiceDefinition("8893bc5b-35b2-4be7-83cb-99e683551db4")
	url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
		"area":            serv.ServiceType,
		"resource":        serv.DisplayName,
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanId,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineId,
	}, map[string]string{})
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.Encode(wrap)

	poolsreq, _ := http.NewRequest("PATCH", url, buf)
	poolsreq.Header["Authorization"] = []string{"bearer " + token}
	AddContentType(poolsreq.Header, "6.0-preview")
	AddHeaders(poolsreq.Header)
	poolsresp, _ := c.Do(poolsreq)

	if poolsresp.StatusCode != 200 {
		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		fmt.Println(string(bytes))
		fmt.Println(buf.String())
	} else {
		// dec := json.NewDecoder(poolsresp.Body)
		// dec.Decode(message)
		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		fmt.Println(string(bytes))
		fmt.Println(buf.String())
	}
}

func UploadLogFile(con *ConnectionData, c *http.Client, tenantUrl string, timelineId string, jobreq *AgentJobRequestMessage, token string, logContent string) int {
	serv := con.GetServiceDefinition("46f5667d-263a-4684-91b1-dff7fdcf64e2")
	log := &TaskLog{}
	{
		url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
			"area":            serv.ServiceType,
			"resource":        serv.DisplayName,
			"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
			"planId":          jobreq.Plan.PlanId,
			"hubName":         jobreq.Plan.PlanType,
			"timelineId":      timelineId,
		}, map[string]string{})

		p := "logs/" + uuid.NewString()
		log.Path = &p
		log.CreatedOn = "2021-05-22T00:00:00"
		log.LastChangedOn = "2021-05-22T00:00:00"

		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.Encode(log)

		poolsreq, _ := http.NewRequest("POST", url, buf)
		AddBearer(poolsreq.Header, token)
		AddContentType(poolsreq.Header, "6.0-preview")
		AddHeaders(poolsreq.Header)
		poolsresp, _ := c.Do(poolsreq)

		if poolsresp.StatusCode != 200 {
			bytes, _ := ioutil.ReadAll(poolsresp.Body)
			fmt.Println(string(bytes))
			fmt.Println(buf.String())
		} else {
			dec := json.NewDecoder(poolsresp.Body)
			dec.Decode(log)
			// bytes, _ := ioutil.ReadAll(poolsresp.Body)
			// fmt.Println(string(bytes))
			// fmt.Println(buf.String())
		}
	}
	{
		url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
			"area":            serv.ServiceType,
			"resource":        serv.DisplayName,
			"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
			"planId":          jobreq.Plan.PlanId,
			"hubName":         jobreq.Plan.PlanType,
			"timelineId":      timelineId,
			"logId":           fmt.Sprint(log.Id),
		}, map[string]string{})

		poolsreq, _ := http.NewRequest("POST", url, bytes.NewBufferString(logContent))
		AddBearer(poolsreq.Header, token)
		AddContentType(poolsreq.Header, "6.0-preview")
		AddHeaders(poolsreq.Header)
		poolsresp, _ := c.Do(poolsreq)

		if poolsresp.StatusCode != 200 {
			bytes, _ := ioutil.ReadAll(poolsresp.Body)
			fmt.Println(string(bytes))
		} else {
			bytes, _ := ioutil.ReadAll(poolsresp.Body)
			fmt.Println(string(bytes))
		}
	}
	return log.Id
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
		f.startLine = 1
		if f.current != nil {
			if f.rc.StepResults[f.current.RefName].Success {
				f.current.Complete("Succeeded")
			} else {
				f.current.Complete("Failed")
			}
			f.current.Log = &TaskLogReference{Id: f.uploadLogFile(f.stepBuffer.String())}
		}
		f.stepBuffer = &bytes.Buffer{}
		for i := range f.wrap.Value {
			if f.wrap.Value[i].RefName == f.rc.CurrentStep {
				b.WriteString(f.wrap.Value[i].Name)
				b.WriteByte(' ')
				f.current = &f.wrap.Value[i]
				f.current.Start()
				break
			}
		}
		f.updateTimeLine()
	}

	// b.WriteString(f.rc.CurrentStep)
	// b.WriteString(": ")

	for _, v := range f.rqt.MaskHints {
		if strings.ToLower(v.Type) == "regex" {
			r, _ := regexp.Compile(v.Value)
			entry.Message = r.ReplaceAllString(entry.Message, "***")
		}
	}
	for _, v := range f.rqt.Variables {
		if v.IsSecret {
			entry.Message = strings.ReplaceAll(entry.Message, v.Value, "***")
		}
	}

	b.WriteString(entry.Message)

	f.logline(f.startLine, f.current.Id, strings.Trim(b.String(), "\r\n"))
	f.startLine++
	if entry.Data["raw_output"] != true {
		b.WriteByte('\n')
	}
	f.stepBuffer.Write(b.Bytes())
	return b.Bytes(), nil
}

type ConfigureRunner struct {
	Url    string
	Token  string
	Labels []string
	Name   string
}

func (config *ConfigureRunner) Configure() {
	buf := new(bytes.Buffer)
	req := &RunnerAddRemove{}
	req.Url = config.Url
	req.RunnerEvent = "register"
	enc := json.NewEncoder(buf)
	if err := enc.Encode(req); err != nil {
		return
	}
	registerUrl, err := url.Parse(config.Url)
	if err != nil {
		fmt.Printf("Invalid Url: %v\n", config.Url)
		return
	}
	if strings.ToLower(registerUrl.Host) == "github.com" {
		registerUrl.Host = "api." + registerUrl.Host
		registerUrl.Path = "actions/runner-registration"
	} else {
		registerUrl.Path = "api/v3/actions/runner-registration"
	}
	finalregisterUrl := registerUrl.String()
	fmt.Printf("Try to register runner with url: %v\n", finalregisterUrl)
	r, _ := http.NewRequest("POST", finalregisterUrl, buf)
	r.Header["Authorization"] = []string{"RemoteAuth " + config.Token}
	c := &http.Client{}
	resp, err := c.Do(r)
	if err != nil {
		fmt.Printf("Failed to register Runner: %v\n", err)
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("Failed to register Runner with status code: %v\n", resp.StatusCode)
		return
	}

	res := &GitHubAuthResult{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(res); err != nil {
		fmt.Printf("error decoding struct from JSON: %v\n", err)
		return
	}

	{
		b, _ := json.MarshalIndent(res, "", "    ")
		ioutil.WriteFile("auth.json", b, 0777)
	}
	connectionData_ := GetConnectionData(c, res.TenantUrl)

	{
		serv := connectionData_.GetServiceDefinition("a8c47e17-4d56-4a56-92bb-de7ea7dc65be")
		tenantUrl := res.TenantUrl
		url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
			"area":     serv.ServiceType,
			"resource": serv.DisplayName,
		}, map[string]string{})

		poolsreq, _ := http.NewRequest("GET", url, nil)
		AddBearer(poolsreq.Header, res.Token)
		poolsresp, _ := c.Do(poolsreq)

		bytes, _ := ioutil.ReadAll(poolsresp.Body)

		fmt.Println(string(bytes))
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ioutil.WriteFile("cred.pkcs1", x509.MarshalPKCS1PrivateKey(key), 0777)

	taskAgent := &TaskAgent{}
	taskAgent.Authorization = TaskAgentAuthorization{}
	bs := make([]byte, 4)
	ui := uint32(key.E)
	binary.BigEndian.PutUint32(bs, ui)
	expof := 0
	for ; expof < 3 && bs[expof] == 0; expof++ {
	}
	taskAgent.Authorization.PublicKey = TaskAgentPublicKey{Exponent: base64.StdEncoding.EncodeToString(bs[expof:]), Modulus: base64.StdEncoding.EncodeToString(key.N.Bytes())}
	taskAgent.Version = "3.0.0"
	taskAgent.OSDescription = "golang"
	taskAgent.Labels = make([]AgentLabel, 1+len(config.Labels))
	taskAgent.Labels[0] = AgentLabel{Name: "self-hosted", Type: "system"}
	for i := 1; i <= len(config.Labels); i++ {
		taskAgent.Labels[i] = AgentLabel{Name: config.Labels[i-1], Type: "user"}
	}
	taskAgent.MaxParallelism = 1
	if config.Name != "" {
		taskAgent.Name = config.Name
	} else {
		taskAgent.Name = "golang_" + uuid.NewString()
	}
	taskAgent.ProvisioningState = "Provisioned"
	taskAgent.CreatedOn = "2021-05-22T00:00:00"
	{
		serv := connectionData_.GetServiceDefinition("e298ef32-5878-4cab-993c-043836571f42")
		tenantUrl := res.TenantUrl
		url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
			"area":     serv.ServiceType,
			"resource": serv.DisplayName,
			"poolId":   fmt.Sprint(1),
		}, map[string]string{})
		{
			poolsreq, _ := http.NewRequest("GET", url, nil)
			AddBearer(poolsreq.Header, res.Token)
			AddContentType(poolsreq.Header, "6.0-preview.2")
			poolsresp, _ := c.Do(poolsreq)

			bytes, _ := ioutil.ReadAll(poolsresp.Body)

			fmt.Println(string(bytes))
		}
		{
			buf := new(bytes.Buffer)
			enc := json.NewEncoder(buf)
			enc.Encode(taskAgent)

			poolsreq, _ := http.NewRequest("POST", url, buf)
			AddBearer(poolsreq.Header, res.Token)
			AddContentType(poolsreq.Header, "6.0-preview.2")
			AddHeaders(poolsreq.Header)
			poolsresp, _ := c.Do(poolsreq)

			if poolsresp.StatusCode != 200 {
				bytes, _ := ioutil.ReadAll(poolsresp.Body)
				fmt.Println(string(bytes))
				fmt.Println(buf.String())
			} else {
				dec := json.NewDecoder(poolsresp.Body)
				dec.Decode(taskAgent)
			}
		}
	}
	b, _ := json.MarshalIndent(taskAgent, "", "    ")
	ioutil.WriteFile("agent.json", b, 0777)
}

type RunRunner struct {
	Once bool
}

func (taskAgent *TaskAgent) Authorize(c *http.Client, key interface{}) (*VssOAuthTokenResponse, error) {
	tokenresp := &VssOAuthTokenResponse{}
	now := time.Now().UTC()
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
	poolsresp, _ := c.Do(poolsreq)
	if poolsresp.StatusCode != 200 {
		bytes, _ := ioutil.ReadAll(poolsresp.Body)
		return nil, errors.New("Failed to Authorize, service reponded with code " + fmt.Sprint(poolsresp.StatusCode) + ": " + string(bytes))
	} else {
		dec := json.NewDecoder(poolsresp.Body)
		if err := dec.Decode(tokenresp); err != nil {
			return nil, err
		}
		return tokenresp, nil
	}
}

func (run *RunRunner) Run() {
	// trap Ctrl+C
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)
	defer func() {
		signal.Stop(channel)
	}()
	poolId := 1
	c := &http.Client{}
	taskAgent := &TaskAgent{}
	var key *rsa.PrivateKey
	var err error
	req := &GitHubAuthResult{}
	{
		cont, _ := ioutil.ReadFile("agent.json")
		json.Unmarshal(cont, taskAgent)
	}
	{
		cont, err := ioutil.ReadFile("cred.pkcs1")
		if err != nil {
			return
		}
		key, err = x509.ParsePKCS1PrivateKey(cont)
		if err != nil {
			return
		}
	}
	if err != nil {
		return
	}
	{
		cont, _ := ioutil.ReadFile("auth.json")
		json.Unmarshal(cont, req)
	}

	tokenresp, err := taskAgent.Authorize(c, key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	connectionData_ := GetConnectionData(c, req.TenantUrl)

	session, b := taskAgent.CreateSession(connectionData_, c, req.TenantUrl, key, tokenresp.AccessToken)
	defer session.Delete(connectionData_, c, req.TenantUrl, tokenresp.AccessToken)
	for !run.Once {
		message := &TaskAgentMessage{}
		success := false
		for !success {
			serv := connectionData_.GetServiceDefinition("c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7")
			url := BuildUrl(req.TenantUrl, serv.RelativePath, map[string]string{
				"area":     serv.ServiceType,
				"resource": serv.DisplayName,
				"poolId":   fmt.Sprint(poolId),
			}, map[string]string{
				"sessionId": session.SessionId,
			})
			//TODO lastMessageId=
			poolsreq, _ := http.NewRequest("GET", url, nil)
			AddBearer(poolsreq.Header, tokenresp.AccessToken)
			AddContentType(poolsreq.Header, "6.0-preview")
			AddHeaders(poolsreq.Header)
			poolsresp, _ := c.Do(poolsreq)

			if poolsresp.StatusCode != 200 {
				if poolsresp.StatusCode >= 200 && poolsresp.StatusCode < 300 {
					select {
					case <-channel:
						fmt.Print("CTRL+C received, stopping")
						return
					default:
					}
					continue
				}
				// The AccessToken expires every hour
				if poolsresp.StatusCode == 401 {
					tokenresp_, err := taskAgent.Authorize(c, key)
					if err != nil {
						fmt.Println(err.Error())
						return
					}
					tokenresp.AccessToken = tokenresp_.AccessToken
					tokenresp.ExpiresIn = tokenresp_.ExpiresIn
					tokenresp.TokenType = tokenresp_.TokenType
					continue
				}
				bytes, _ := ioutil.ReadAll(poolsresp.Body)
				fmt.Println(string(bytes))
				fmt.Printf("Failed to get message: %v", poolsresp.StatusCode)
				return
			} else {
				success = true
				dec := json.NewDecoder(poolsresp.Body)
				dec.Decode(message)
				for {
					url := BuildUrl(req.TenantUrl, serv.RelativePath, map[string]string{
						"area":      serv.ServiceType,
						"resource":  serv.DisplayName,
						"poolId":    fmt.Sprint(poolId),
						"messageId": fmt.Sprint(message.MessageId),
					}, map[string]string{
						"sessionId": session.SessionId,
					})
					poolsreq, _ := http.NewRequest("DELETE", url, nil)
					AddBearer(poolsreq.Header, tokenresp.AccessToken)
					AddContentType(poolsreq.Header, "6.0-preview")
					AddHeaders(poolsreq.Header)
					poolsresp, _ := c.Do(poolsreq)
					if poolsresp.StatusCode != 200 {
						if poolsresp.StatusCode >= 200 && poolsresp.StatusCode < 300 {
							select {
							case <-channel:
								fmt.Print("CTRL+C received, stopping")
								return
							default:
							}
							break
						}
						// The AccessToken expires every hour
						if poolsresp.StatusCode == 401 {
							tokenresp_, err := taskAgent.Authorize(c, key)
							if err != nil {
								fmt.Println(err.Error())
								return
							}
							tokenresp.AccessToken = tokenresp_.AccessToken
							tokenresp.ExpiresIn = tokenresp_.ExpiresIn
							tokenresp.TokenType = tokenresp_.TokenType
							continue
						}
						fmt.Print("Failed to delete Message")
						return
					} else {
						break
					}
				}
			}
		}
		iv, _ := base64.StdEncoding.DecodeString(message.IV)
		src, _ := base64.StdEncoding.DecodeString(message.Body)
		cbcdec := cipher.NewCBCDecrypter(b, iv)
		cbcdec.CryptBlocks(src, src)
		maxlen := b.BlockSize()
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
		fmt.Println(string(src[off:validlen]))
		jobreq := &AgentJobRequestMessage{}
		{
			dec := json.NewDecoder(bytes.NewReader(src[off:validlen]))
			dec.Decode(jobreq)
		}
		if jobreq.Resources == nil {
			fmt.Println("Missing Job Resources")
			continue
		}
		if jobreq.Resources.Endpoints == nil {
			fmt.Println("Missing Job Resources Endpoints")
			continue
		}
		jobToken := tokenresp.AccessToken
		jobTenant := req.TenantUrl
		jobConnectionData := connectionData_
		for _, endpoint := range jobreq.Resources.Endpoints {
			if endpoint.Name == "SystemVssConnection" && endpoint.Authorization.Parameters != nil && endpoint.Authorization.Parameters["AccessToken"] != "" {
				jobToken = endpoint.Authorization.Parameters["AccessToken"]
				if jobTenant != endpoint.Url {
					jobTenant = endpoint.Url
					jobConnectionData = GetConnectionData(c, jobTenant)
				}
			}
		}

		rqt := jobreq
		githubCtx := rqt.ContextData["github"].ToRawObject()
		secrets := map[string]string{}
		for k, v := range rqt.Variables {
			if v.IsSecret && k != "system.github.token" {
				secrets[k] = v.Value
			}
		}
		secrets["GITHUB_TOKEN"] = rqt.Variables["system.github.token"].Value
		matrix, ok := rqt.ContextData["matrix"].ToRawObject().(map[string]interface{})
		if !ok {
			matrix = make(map[string]interface{})
		}
		env := make(map[string]string)
		if rqt.EnvironmentVariables != nil {
			for _, rawenv := range rqt.EnvironmentVariables {
				for k, v := range rawenv.ToRawObject().(map[interface{}]interface{}) {
					env[k.(string)] = v.(string)
				}
			}
		}

		defaults := model.Defaults{}
		if rqt.Defaults != nil {
			for _, rawenv := range rqt.Defaults {
				b, _ := json.Marshal(rawenv.ToRawObject())
				json.Unmarshal(b, &defaults)
			}
		}
		steps := []*model.Step{}
		for _, step := range rqt.Steps {
			st := strings.ToLower(step.Reference.Type)
			inputs := make(map[interface{}]interface{})
			if step.Inputs != nil {
				inputs = step.Inputs.ToRawObject().(map[interface{}]interface{})
			}
			env := make(map[string]string)
			if step.Environment != nil {
				for k, v := range step.Environment.ToRawObject().(map[interface{}]interface{}) {
					env[k.(string)] = v.(string)
				}
			}

			rawwd, haswd := inputs["workingDirectory"]
			var wd string
			if haswd {
				wd = rawwd.(string)
			} else {
				wd = ""
			}
			continueOnError := false
			if step.ContinueOnError != nil {
				continueOnError = step.ContinueOnError.ToRawObject().(bool)
			}
			var timeoutMinutes int64 = 0
			if step.TimeoutInMinutes != nil {
				timeoutMinutes = int64(step.TimeoutInMinutes.ToRawObject().(float64))
			}
			var displayName string = ""
			if step.DisplayNameToken != nil {
				displayName = step.DisplayNameToken.ToRawObject().(string)
			}
			if step.ContextName == "" {
				step.ContextName = "___" + uuid.New().String()
			}

			switch st {
			case "script":
				rawshell, hasshell := inputs["shell"]
				var shell string
				if hasshell {
					shell = rawshell.(string)
				} else {
					shell = ""
				}
				steps = append(steps, &model.Step{
					ID:               step.ContextName,
					If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
					Name:             displayName,
					Run:              inputs["script"].(string),
					WorkingDirectory: wd,
					Shell:            shell,
					ContinueOnError:  continueOnError,
					TimeoutMinutes:   timeoutMinutes,
					Env:              env,
				})
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
					k := k.(string)
					switch k {
					case "workingDirectory":
					default:
						with[k] = v.(string)
					}
				}

				steps = append(steps, &model.Step{
					ID:               step.ContextName,
					If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
					Name:             displayName,
					Uses:             uses,
					WorkingDirectory: wd,
					With:             with,
					ContinueOnError:  continueOnError,
					TimeoutMinutes:   timeoutMinutes,
					Env:              env,
				})
			}
		}
		rawContainer := yaml.Node{}
		if rqt.JobContainer != nil {
			rawContainer = *rqt.JobContainer.ToYamlNode()
		}
		services := make(map[string]*model.ContainerSpec)
		if rqt.JobServiceContainers != nil {
			for name, rawcontainer := range rqt.JobServiceContainers.ToRawObject().(map[interface{}]interface{}) {
				spec := &model.ContainerSpec{}
				b, _ := json.Marshal(rawcontainer)
				json.Unmarshal(b, &spec)
				services[name.(string)] = spec
			}
		}
		var payload string
		{
			e, _ := json.Marshal(githubCtx.(map[string]interface{})["event"])
			payload = string(e)
		}
		rc := &runner.RunContext{
			Config: &runner.Config{
				Workdir: ".",
				Secrets: secrets,
				Platforms: map[string]string{
					"dummy": "catthehacker/ubuntu:act-latest",
				},
				LogOutput:      true,
				EventName:      githubCtx.(map[string]interface{})["event_name"].(string),
				GitHubInstance: githubCtx.(map[string]interface{})["server_url"].(string)[8:],
			},
			Env: env,
			Run: &model.Run{
				JobID: rqt.JobId,
				Workflow: &model.Workflow{
					Name:     githubCtx.(map[string]interface{})["workflow"].(string),
					Defaults: defaults,
					Jobs: map[string]*model.Job{
						rqt.JobId: {
							Name:         rqt.JobDisplayName,
							RawRunsOn:    yaml.Node{Kind: yaml.ScalarNode, Value: "dummy"},
							Steps:        steps,
							RawContainer: rawContainer,
							Services:     services,
						},
					},
				},
			},
			Matrix:      matrix,
			StepResults: make(map[string]*runner.StepResult),
			EventJSON:   payload,
		}

		val, _ := json.Marshal(githubCtx)
		fmt.Println(string(val))
		sv := string(val)
		rc.GithubContextBase = &sv
		rc.JobName = "beta"

		ctx := context.Background()

		ee := rc.NewExpressionEvaluator()
		rc.ExprEval = ee
		logger := logrus.New()

		buf := new(bytes.Buffer)

		formatter := new(ghaFormatter)
		formatter.rc = rc
		formatter.rqt = rqt

		logger.SetFormatter(formatter)
		logger.SetOutput(buf)
		logger.SetLevel(logrus.DebugLevel)

		rc.CurrentStep = "__setup"
		rc.StepResults[rc.CurrentStep] = &runner.StepResult{Success: true}

		wrap := &TimelineRecordWrapper{}
		wrap.Count = int64(len(steps)) + 2
		wrap.Value = make([]TimelineRecord, wrap.Count)
		wrap.Value[0] = CreateTimelineEntry("", rqt.JobName, rqt.JobDisplayName)
		wrap.Value[0].Id = rqt.JobId
		wrap.Value[0].Type = "Job"
		wrap.Value[0].Order = 0
		wrap.Value[0].Start()
		wrap.Value[1] = CreateTimelineEntry(rqt.JobId, "__setup", "Setup Job")
		wrap.Value[1].Order = 1
		for i := 0; i < len(steps); i++ {
			wrap.Value[i+2] = CreateTimelineEntry(rqt.JobId, steps[i].ID, steps[i].String())
			wrap.Value[i+2].Order = int32(i + 2)
		}
		UpdateTimeLine(jobConnectionData, c, jobTenant, jobreq.Timeline.Id, jobreq, wrap, jobToken)
		{
			formatter.updateTimeLine = func() {
				UpdateTimeLine(jobConnectionData, c, jobTenant, jobreq.Timeline.Id, jobreq, wrap, jobToken)
			}
			formatter.uploadLogFile = func(log string) int {
				return UploadLogFile(jobConnectionData, c, jobTenant, jobreq.Timeline.Id, jobreq, jobToken, log)
			}
		}
		{
			serv := jobConnectionData.GetServiceDefinition("858983e4-19bd-4c5e-864c-507b59b58b12")
			tenantUrl := jobTenant
			formatter.logline = func(startLine int64, recordId string, line string) {
				url := BuildUrl(tenantUrl, serv.RelativePath, map[string]string{
					"area":            serv.ServiceType,
					"resource":        serv.DisplayName,
					"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
					"planId":          jobreq.Plan.PlanId,
					"hubName":         jobreq.Plan.PlanType,
					"timelineId":      jobreq.Timeline.Id,
					"recordId":        recordId,
				}, map[string]string{})

				buf := new(bytes.Buffer)
				enc := json.NewEncoder(buf)
				lines := &TimelineRecordFeedLinesWrapper{}
				lines.Count = 1
				lines.StartLine = &startLine
				lines.StepId = recordId
				lines.Value = []string{line}
				enc.Encode(lines)
				poolsreq, _ := http.NewRequest("POST", url, buf)
				AddBearer(poolsreq.Header, jobToken)
				AddContentType(poolsreq.Header, "6.0-preview")
				AddHeaders(poolsreq.Header)
				c.Do(poolsreq)
			}
		}
		formatter.wrap = wrap

		rc.Executor()(common.WithLogger(ctx, logger))
		jobStatus := "success"
		for _, stepStatus := range rc.StepResults {
			if !stepStatus.Success {
				jobStatus = "failure"
				break
			}
		}
		if jobStatus == "success" {
			wrap.Value[0].Complete("Succeeded")
		} else {
			wrap.Value[0].Complete("Failed")
		}
		{
			f := formatter
			f.startLine = 1
			if f.current != nil {
				if f.rc.StepResults[f.current.RefName].Success {
					f.current.Complete("Succeeded")
				} else {
					f.current.Complete("Failed")
				}
				f.current.Log = &TaskLogReference{Id: f.uploadLogFile(f.stepBuffer.String())}
			}
		}

		str := buf.String()
		print(str)

		UpdateTimeLine(jobConnectionData, c, jobTenant, jobreq.Timeline.Id, jobreq, wrap, jobToken)

		{
			finish := &JobEvent{
				Name:      "JobCompleted",
				JobId:     jobreq.JobId,
				RequestId: jobreq.RequestId,
				Result:    "Failed",
			}
			if jobStatus == "success" {
				finish.Result = "Succeeded"
			}
			serv := jobConnectionData.GetServiceDefinition("557624af-b29e-4c20-8ab0-0399d2204f3f")
			url := BuildUrl(jobTenant, serv.RelativePath, map[string]string{
				"area":            serv.ServiceType,
				"resource":        serv.DisplayName,
				"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
				"planId":          jobreq.Plan.PlanId,
				"hubName":         jobreq.Plan.PlanType,
			}, map[string]string{})
			buf := new(bytes.Buffer)
			enc := json.NewEncoder(buf)
			enc.Encode(finish)
			poolsreq, _ := http.NewRequest("POST", url, buf)
			AddBearer(poolsreq.Header, jobToken)
			AddContentType(poolsreq.Header, "6.0-preview")
			AddHeaders(poolsreq.Header)
			poolsresp, _ := c.Do(poolsreq)
			if poolsresp.StatusCode != 200 {
				fmt.Println("Failed to send finish job event")
				return
			}
		}
	}
}

func main() {
	config := &ConfigureRunner{}
	run := &RunRunner{}
	var cmdConfigure = &cobra.Command{
		Use:   "Configure",
		Short: "Configure your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			config.Configure()
		},
	}

	cmdConfigure.Flags().StringVar(&config.Url, "url", "", "url of your repository or enterprise")
	cmdConfigure.Flags().StringVar(&config.Token, "token", "", "runner registration token")
	cmdConfigure.Flags().StringSliceVarP(&config.Labels, "label", "l", []string{}, "label for your new runner")
	cmdConfigure.Flags().StringVar(&config.Name, "name", "", "custom runner name")

	var cmdRun = &cobra.Command{
		Use:   "Run",
		Short: "run your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			run.Run()
		},
	}

	cmdRun.Flags().BoolVar(&run.Once, "once", false, "only execute one job and exit")

	var rootCmd = &cobra.Command{Use: "github-actions-act-runner"}
	rootCmd.AddCommand(cmdConfigure, cmdRun)
	rootCmd.Execute()
}
