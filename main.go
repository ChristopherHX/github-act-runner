package main

import (
	"bytes"
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
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
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
		var typ int32 = 3
		ctx.Type = &typ
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
		return ctx.StringValue
	case 1:
		a := make([]interface{}, 0)
		for _, v := range *ctx.ArrayValue {
			a = append(a, v.ToRawObject())
		}
		return a
	case 2:
		m := make(map[string]interface{})
		for _, v := range *ctx.DictionaryValue {
			m[v.Key] = v.Value.ToRawObject()
		}
		return m
	case 3:
		return ctx.BoolValue
	case 4:
		return ctx.NumberValue
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

func main() {
	c, _ := ioutil.ReadFile("jobreq2.json")
	// var rqt *AgentJobRequestMessage
	rqt := &AgentJobRequestMessage{}
	err := json.Unmarshal(c, rqt)
	if err != nil {
		return
	}
	obj := rqt.ContextData["github"].ToRawObject()
	val, _ := json.Marshal(obj)
	fmt.Println(string(val))
	t := &TaskAgent{}
	m, _ := json.Marshal(t)
	fmt.Println(string(m))

	buf := new(bytes.Buffer)
	req := &RunnerAddRemove{}
	req.Url = "https://github.com/ChristopherHX/ghat2"
	// req.Url = "http://192.168.178.20:5000/ChristopherHX/ghat"
	req.RunnerEvent = "register"
	enc := json.NewEncoder(buf)
	if err := enc.Encode(req); err != nil {
		return
	}
	if false {
		// "https://api.github.com/actions/runner-registration"
		// "http://192.168.178.20:5000/api/v3/actions/runner-registration"
		r, _ := http.NewRequest("POST", "https://api.github.com/actions/runner-registration", buf)
		// r, _ := http.NewRequest("POST", "http://192.168.178.20:5000/api/v3/actions/runner-registration", buf)
		r.Header["Authorization"] = []string{"RemoteAuth AKWETFMWLIXPGXUXVVOX7BTAVA5KO"}
		c := &http.Client{}
		resp, err := c.Do(r)
		if err != nil {
			fmt.Printf("error req: %v\n", err)
		}

		req := &GitHubAuthResult{}
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(req); err != nil {
			fmt.Printf("error decoding struct from JSON: %v\n", err)
		}

		{
			b, _ := json.MarshalIndent(req, "", "    ")
			ioutil.WriteFile("auth.json", b, 0777)
		}
		connectionData_ := GetConnectionData(c, req.TenantUrl)

		poolId := 1

		for i := 0; i < len(connectionData_.LocationServiceData.ServiceDefinitions); i++ {
			if connectionData_.LocationServiceData.ServiceDefinitions[i].Identifier == "a8c47e17-4d56-4a56-92bb-de7ea7dc65be" {
				url2, _ := url.Parse(req.TenantUrl)
				url := connectionData_.LocationServiceData.ServiceDefinitions[i].RelativePath
				url = strings.ReplaceAll(url, "{area}", connectionData_.LocationServiceData.ServiceDefinitions[i].ServiceType)
				url = strings.ReplaceAll(url, "{resource}", connectionData_.LocationServiceData.ServiceDefinitions[i].DisplayName)
				re := regexp.MustCompile(`/*\{[^\}]+\}`)
				url = re.ReplaceAllString(url, "")
				url2.Path = path.Join(url2.Path, url)
				poolsreq, _ := http.NewRequest("GET", url2.String(), nil)
				poolsreq.Header["Authorization"] = []string{"bearer " + req.Token}
				poolsresp, _ := c.Do(poolsreq)

				bytes, _ := ioutil.ReadAll(poolsresp.Body)

				fmt.Println(string(bytes))
				break
			}
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
		taskAgent.Labels = make([]AgentLabel, 3)
		taskAgent.Labels[0] = AgentLabel{Name: "self-hosted", Type: "system"}
		taskAgent.Labels[1] = AgentLabel{Name: "scratch", Type: "system"}
		taskAgent.Labels[2] = AgentLabel{Name: "golang", Type: "system"}
		taskAgent.MaxParallelism = 1
		taskAgent.Name = "golang_" + uuid.NewString()
		taskAgent.ProvisioningState = "Provisioned"
		taskAgent.CreatedOn = "2021-05-22T00:00:00"
		for i := 0; i < len(connectionData_.LocationServiceData.ServiceDefinitions); i++ {
			if connectionData_.LocationServiceData.ServiceDefinitions[i].Identifier == "e298ef32-5878-4cab-993c-043836571f42" {
				url2, _ := url.Parse(req.TenantUrl)
				url := connectionData_.LocationServiceData.ServiceDefinitions[i].RelativePath
				url = strings.ReplaceAll(url, "{area}", connectionData_.LocationServiceData.ServiceDefinitions[i].ServiceType)
				url = strings.ReplaceAll(url, "{resource}", connectionData_.LocationServiceData.ServiceDefinitions[i].DisplayName)
				url = strings.ReplaceAll(url, "{poolId}", fmt.Sprint(poolId))
				re := regexp.MustCompile(`/*\{[^\}]+\}`)
				url = re.ReplaceAllString(url, "")
				url2.Path = path.Join(url2.Path, url)
				poolsreq, _ := http.NewRequest("GET", url2.String(), nil)
				poolsreq.Header["Authorization"] = []string{"bearer " + req.Token}
				poolsreq.Header["Accept"] = []string{"application/json; api-version=6.0-preview.2"}
				poolsresp, _ := c.Do(poolsreq)

				bytes, _ := ioutil.ReadAll(poolsresp.Body)

				fmt.Println(string(bytes))
				break
			}
		}
		for i := 0; i < len(connectionData_.LocationServiceData.ServiceDefinitions); i++ {
			if connectionData_.LocationServiceData.ServiceDefinitions[i].Identifier == "e298ef32-5878-4cab-993c-043836571f42" {
				url2, _ := url.Parse(req.TenantUrl)
				url := connectionData_.LocationServiceData.ServiceDefinitions[i].RelativePath
				url = strings.ReplaceAll(url, "{area}", connectionData_.LocationServiceData.ServiceDefinitions[i].ServiceType)
				url = strings.ReplaceAll(url, "{resource}", connectionData_.LocationServiceData.ServiceDefinitions[i].DisplayName)
				url = strings.ReplaceAll(url, "{poolId}", fmt.Sprint(poolId))
				re := regexp.MustCompile(`/*\{[^\}]+\}`)
				url = re.ReplaceAllString(url, "")
				url2.Path = path.Join(url2.Path, url)
				buf := new(bytes.Buffer)
				enc := json.NewEncoder(buf)
				enc.Encode(taskAgent)

				poolsreq, _ := http.NewRequest("POST", url2.String(), buf)
				poolsreq.Header["Authorization"] = []string{"bearer " + req.Token}
				poolsreq.Header["Content-Type"] = []string{"application/json; charset=utf-8; api-version=6.0-preview.2"}
				poolsreq.Header["Accept"] = []string{"application/json; api-version=6.0-preview.2"}
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
				break
			}
		}
		b, _ := json.MarshalIndent(taskAgent, "", "    ")
		ioutil.WriteFile("agent.json", b, 0777)
	}
	{
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

		tokenresp := &VssOAuthTokenResponse{}
		{
			now := time.Now()
			token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": taskAgent.Authorization.ClientId, "iss": taskAgent.Authorization.ClientId, "aud": taskAgent.Authorization.AuthorizationUrl, "nbf": now, "iat": now, "exp": now.Add(time.Minute * 5), "jti": uuid.New().String()})
			stkn, _ := token2.SignedString(key)
			fmt.Println(stkn)

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
				fmt.Println(string(bytes))
				fmt.Println(buf.String())
			} else {
				dec := json.NewDecoder(poolsresp.Body)
				dec.Decode(tokenresp)
			}

		}

		connectionData_ := GetConnectionData(c, req.TenantUrl)

		session, b := taskAgent.CreateSession(connectionData_, c, req.TenantUrl, key, tokenresp.AccessToken)
		message := &TaskAgentMessage{}
		success := false
		for !success {
			for i := 0; i < len(connectionData_.LocationServiceData.ServiceDefinitions); i++ {
				if connectionData_.LocationServiceData.ServiceDefinitions[i].Identifier == "c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7" {
					url2, _ := url.Parse(req.TenantUrl)
					url := connectionData_.LocationServiceData.ServiceDefinitions[i].RelativePath
					url = strings.ReplaceAll(url, "{area}", connectionData_.LocationServiceData.ServiceDefinitions[i].ServiceType)
					url = strings.ReplaceAll(url, "{resource}", connectionData_.LocationServiceData.ServiceDefinitions[i].DisplayName)
					url = strings.ReplaceAll(url, "{poolId}", fmt.Sprint(poolId))
					q := url2.Query()
					q.Add("sessionId", session.SessionId)
					url2.RawQuery = q.Encode()
					re := regexp.MustCompile(`/*\{[^\}]+\}`)
					url = re.ReplaceAllString(url, "")
					url2.Path = path.Join(url2.Path, url)
					buf := new(bytes.Buffer)
					enc := json.NewEncoder(buf)
					enc.Encode(session)
					//TODO lastMessageId=
					poolsreq, _ := http.NewRequest("GET", url2.String(), buf)
					poolsreq.Header["Authorization"] = []string{"bearer " + tokenresp.AccessToken}
					AddContentType(poolsreq.Header, "6.0-preview")
					AddHeaders(poolsreq.Header)
					poolsresp, _ := c.Do(poolsreq)

					if poolsresp.StatusCode != 200 {
						bytes, _ := ioutil.ReadAll(poolsresp.Body)
						fmt.Println(string(bytes))
						fmt.Println(buf.String())
					} else {
						success = true
						dec := json.NewDecoder(poolsresp.Body)
						dec.Decode(message)
						serv := connectionData_.LocationServiceData.ServiceDefinitions[i]
						url := BuildUrl(req.TenantUrl, serv.RelativePath, map[string]string{
							"area":      serv.ServiceType,
							"resource":  serv.DisplayName,
							"poolId":    fmt.Sprint(poolId),
							"messageId": fmt.Sprint(message.MessageId),
						}, map[string]string{
							"sessionId": session.SessionId,
						})
						poolsreq, _ := http.NewRequest("DELETE", url, buf)
						poolsreq.Header["Authorization"] = []string{"bearer " + tokenresp.AccessToken}
						AddContentType(poolsreq.Header, "6.0-preview")
						AddHeaders(poolsreq.Header)
						poolsresp, _ := c.Do(poolsreq)
						if poolsresp.StatusCode != 200 {
							return
						}
					}

					break
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
		fmt.Println(jobreq.JobName)
		// jobreq.Timeline.Id
		wrap := &TimelineRecordWrapper{}
		wrap.Count = 3
		wrap.Value = make([]TimelineRecord, 3)
		wrap.Value[0] = TimelineRecord{}
		wrap.Value[0].Id = jobreq.JobId
		wrap.Value[0].RefName = jobreq.JobName
		wrap.Value[0].Name = jobreq.JobDisplayName
		wrap.Value[0].Type = "Job"
		wrap.Value[0].WorkerName = "golang-go"
		wrap.Value[0].State = "InProgress"
		wrap.Value[0].StartTime = "2021-05-22T00:00:00"
		wrap.Value[0].LastModified = "2021-05-22T00:00:00"
		// wrap.Value[0].StartTime = time.Now()

		suc := "succeeded"
		wrap.Value[1] = TimelineRecord{}
		wrap.Value[1].StartTime = "2021-05-22T00:00:00"
		wrap.Value[1].Result = &suc
		wrap.Value[1].Id = uuid.NewString()
		wrap.Value[1].RefName = "init"
		wrap.Value[1].Name = "initializeing"
		wrap.Value[1].Type = "Task"
		wrap.Value[1].WorkerName = "golang-go"
		wrap.Value[1].ParentId = jobreq.JobId
		wrap.Value[1].State = "Completed"
		wrap.Value[1].LastModified = "2021-05-22T00:00:00"
		wrap.Value[1].Order = 1

		wrap.Value[1].Log = &TaskLogReference{}
		wrap.Value[1].Log.Id = UploadLogFile(connectionData_, c, req.TenantUrl, jobreq.Timeline.Id, jobreq, tokenresp.AccessToken, "just for fun!\nNext Level\nBye")
		//
		wrap.Value[2] = TimelineRecord{}
		wrap.Value[2].StartTime = "2021-05-22T00:00:00"
		wrap.Value[2].Id = uuid.NewString()
		wrap.Value[2].RefName = "running"
		wrap.Value[2].Name = "Running"
		wrap.Value[2].Type = "Task"
		wrap.Value[2].WorkerName = "golang-go"
		wrap.Value[2].ParentId = jobreq.JobId
		wrap.Value[2].State = "InProgress"
		wrap.Value[2].LastModified = "2021-05-22T00:00:00"
		wrap.Value[2].Order = 2

		UpdateTimeLine(connectionData_, c, req.TenantUrl, jobreq.Timeline.Id, jobreq, wrap, tokenresp.AccessToken)

		for counter := 0; counter < 10; counter++ {
			for i := 0; i < len(connectionData_.LocationServiceData.ServiceDefinitions); i++ {
				if connectionData_.LocationServiceData.ServiceDefinitions[i].Identifier == "858983e4-19bd-4c5e-864c-507b59b58b12" {
					url2, _ := url.Parse(req.TenantUrl)
					url := connectionData_.LocationServiceData.ServiceDefinitions[i].RelativePath
					url = strings.ReplaceAll(url, "{area}", connectionData_.LocationServiceData.ServiceDefinitions[i].ServiceType)
					url = strings.ReplaceAll(url, "{resource}", connectionData_.LocationServiceData.ServiceDefinitions[i].DisplayName)
					url = strings.ReplaceAll(url, "{poolId}", fmt.Sprint(poolId))
					url = strings.ReplaceAll(url, "{sessionId}", session.SessionId)
					url = strings.ReplaceAll(url, "{scopeIdentifier}", jobreq.Plan.ScopeIdentifier)
					url = strings.ReplaceAll(url, "{planId}", jobreq.Plan.PlanId)
					url = strings.ReplaceAll(url, "{hubName}", jobreq.Plan.PlanType)
					url = strings.ReplaceAll(url, "{timelineId}", jobreq.Timeline.Id)
					url = strings.ReplaceAll(url, "{recordId}", wrap.Value[2].Id)

					re := regexp.MustCompile(`/*\{[^\}]+\}`)
					url = re.ReplaceAllString(url, "")
					url2.Path = path.Join(url2.Path, url)
					buf := new(bytes.Buffer)
					enc := json.NewEncoder(buf)
					lines := &TimelineRecordFeedLinesWrapper{}
					lines.Count = 1
					sl := int64(counter)
					lines.StartLine = &sl
					lines.StepId = wrap.Value[2].Id
					lines.Value = []string{"Hello World from go!: " + fmt.Sprint(counter)}
					enc.Encode(lines)
					poolsreq, _ := http.NewRequest("POST", url2.String(), buf)
					poolsreq.Header["Authorization"] = []string{"bearer " + tokenresp.AccessToken}
					AddContentType(poolsreq.Header, "6.0-preview")
					AddHeaders(poolsreq.Header)
					poolsresp, _ := c.Do(poolsreq)

					// bytes, _ := ioutil.ReadAll(poolsresp.Body)

					// fmt.Println(string(bytes))
					if poolsresp.StatusCode != 200 {
						bytes, _ := ioutil.ReadAll(poolsresp.Body)
						fmt.Println(string(bytes))
						fmt.Println(buf.String())
					} else {
						success = true
						// dec := json.NewDecoder(poolsresp.Body)
						// dec.Decode(message)
						bytes, _ := ioutil.ReadAll(poolsresp.Body)
						fmt.Println(string(bytes))
						fmt.Println(buf.String())
					}

					break
				}
			}
			time.Sleep(time.Second)
		}
		wrap.Value[0].Result = &suc
		wrap.Value[0].State = "completed"
		wrap.Value[0].PercentComplete = 100

		wrap.Value[1].PercentComplete = 100
		t := "2021-05-22T00:01:00"
		wrap.Value[0].FinishTime = &t
		wrap.Value[0].LastModified = t
		wrap.Value[2].FinishTime = &t
		wrap.Value[2].LastModified = t
		wrap.Value[2].Result = &suc
		wrap.Value[2].State = "completed"
		wrap.Value[2].PercentComplete = 100
		wrap.Value[1].PercentComplete = 100
		wrap.Value[0].Log = &TaskLogReference{}
		wrap.Value[0].Log.Id = UploadLogFile(connectionData_, c, req.TenantUrl, jobreq.Timeline.Id, jobreq, tokenresp.AccessToken, "just for fun!\nNext Level\nBye\nJobLog?")
		wrap.Value[2].Log = &TaskLogReference{}
		wrap.Value[2].Log.Id = UploadLogFile(connectionData_, c, req.TenantUrl, jobreq.Timeline.Id, jobreq, tokenresp.AccessToken, "JobLog?")

		UpdateTimeLine(connectionData_, c, req.TenantUrl, jobreq.Timeline.Id, jobreq, wrap, tokenresp.AccessToken)
		{
			type JobEvent struct {
				Name               string
				JobId              string
				RequestId          int64
				Result             string
				Outputs            *map[string]VariableValue    `json:"Outputs,omitempty"`
				ActionsEnvironment *ActionsEnvironmentReference `json:"ActionsEnvironment,omitempty"`
			}
			finish := &JobEvent{
				Name:      "JobCompleted",
				JobId:     jobreq.JobId,
				RequestId: jobreq.RequestId,
				// Result:    "Failed",
				Result: "Succeeded",
			}
			serv := connectionData_.GetServiceDefinition("557624af-b29e-4c20-8ab0-0399d2204f3f")
			url := BuildUrl(req.TenantUrl, serv.RelativePath, map[string]string{
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
			AddBearer(poolsreq.Header, tokenresp.AccessToken)
			AddContentType(poolsreq.Header, "6.0-preview")
			AddHeaders(poolsreq.Header)
			poolsresp, _ := c.Do(poolsreq)
			if poolsresp.StatusCode != 200 {
				session.Delete(connectionData_, c, req.TenantUrl, tokenresp.AccessToken)
				return
			}
		}
		session.Delete(connectionData_, c, req.TenantUrl, tokenresp.AccessToken)
	}
}
