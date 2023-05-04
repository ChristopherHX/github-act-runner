package protocol

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/google/uuid"
)

type VssConnection struct {
	Client         *http.Client
	TenantURL      string
	connectionData *ConnectionData
	Token          string
	PoolID         int64
	TaskAgent      *TaskAgent
	Key            *rsa.PrivateKey
	Trace          bool
}

func (vssConnection *VssConnection) BuildURL(relativePath string, ppath map[string]string, query map[string]string) (string, error) {
	url2, err := url.Parse(vssConnection.TenantURL)
	if err != nil {
		return "", err
	}
	url := relativePath
	re := regexp.MustCompile(`/*\{[^\}]+\}`)
	url = re.ReplaceAllStringFunc(url, func(s string) string {
		start := strings.Index(s, "{")
		end := strings.Index(s, "}")
		if val, ok := ppath[s[start+1:end]]; ok {
			return s[0:start] + val
		}
		return ""
	})
	url2.Path = path.Join(url2.Path, url)
	q := url2.Query()
	for p, v := range query {
		q.Add(p, v)
	}
	url2.RawQuery = q.Encode()
	return url2.String(), nil
}

func (vssConnection *VssConnection) HttpClient() *http.Client {
	if vssConnection.Client == nil {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.MaxIdleConns = 1
		customTransport.IdleConnTimeout = 100 * time.Second
		if v, ok := common.LookupEnvBool("SKIP_TLS_CERT_VALIDATION"); ok && v {
			customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		vssConnection.Client = &http.Client{
			Timeout:   100 * time.Second,
			Transport: customTransport,
		}
	}
	return vssConnection.Client
}

func (vssConnection *VssConnection) authorize() (*VssOAuthTokenResponse, error) {
	var authResponse *VssOAuthTokenResponse
	var err error
	authResponse, err = vssConnection.TaskAgent.Authorize(vssConnection.HttpClient(), vssConnection.Key)
	if err == nil {
		return authResponse, nil
	}
	return nil, err
}

func (vssConnection *VssConnection) Request(serviceID string, protocol string, method string, urlParameter map[string]string, queryParameter map[string]string, requestBody interface{}, responseBody interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return vssConnection.RequestWithContext(ctx, serviceID, protocol, method, urlParameter, queryParameter, requestBody, responseBody)
}

func (vssConnection *VssConnection) GetServiceURL(ctx context.Context, serviceID string, urlParameter map[string]string, queryParameter map[string]string) (string, error) {
	if vssConnection.connectionData == nil {
		for i := 1; ; {
			vssConnection.connectionData = vssConnection.GetConnectionData()
			if vssConnection.connectionData != nil {
				break
			}
			maxtime := 60 * 10
			var dtime time.Duration = time.Duration(i) * time.Second
			if i < maxtime {
				i *= 2
			} else {
				dtime = time.Duration(maxtime) * time.Second
			}
			fmt.Printf("Retry retrieving connectiondata from the server in %v seconds\n", dtime)
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("aborted to get connectionData")
			case <-time.After(dtime):
			}
		}
	}

	serv := vssConnection.connectionData.GetServiceDefinition(serviceID)
	if urlParameter == nil {
		urlParameter = map[string]string{}
	}
	urlParameter["area"] = serv.ServiceType
	urlParameter["resource"] = serv.DisplayName
	if queryParameter == nil {
		queryParameter = map[string]string{}
	}
	return vssConnection.BuildURL(serv.RelativePath, urlParameter, queryParameter)
}

func (vssConnection *VssConnection) RequestWithContext(ctx context.Context, serviceID string, protocol string, method string, urlParameter map[string]string, queryParameter map[string]string, requestBody interface{}, responseBody interface{}) error {
	url, err := vssConnection.GetServiceURL(ctx, serviceID, urlParameter, queryParameter)
	if err != nil {
		return err
	}
	return vssConnection.RequestWithContext2(ctx, method, url, protocol, requestBody, responseBody)
}

func extractReader(body interface{}) (io.Reader, []string, error) {
	if body == nil {
		return nil, nil, nil
	}
	if buf, ok := body.(*bytes.Buffer); ok {
		return buf, []string{"application/octet-stream"}, nil
	}
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(body); err != nil {
		return nil, nil, err
	}
	return buf, []string{"application/json; charset=utf-8"}, nil
}

func getHeadersAsString(header http.Header) string {
	headerbuf := new(bytes.Buffer)
	if err := header.Write(headerbuf); err != nil {
		return err.Error()
	}
	return headerbuf.String()
}

func getBodyAsString(body interface{}) string {
	if buf, ok := body.(*bytes.Buffer); ok {
		return buf.String()
	}
	return ""
}

func setResponseBody(r io.Reader, body interface{}) error {
	if body == nil {
		return nil
	}
	if bresponse, ok := body.(*[]byte); ok {
		var err error
		*bresponse, err = ioutil.ReadAll(r)
		if err != nil {
			return err
		}
	} else {
		dec := json.NewDecoder(r)
		if err := dec.Decode(body); err != nil {
			return err
		}
	}
	return nil
}

func (vssConnection *VssConnection) requestWithContextNoAuth(ctx context.Context, method string, requesturl string, apiversion string, requestBody interface{}, responseBody interface{}) (int, error) {
	buf, reqContentType, err := extractReader(requestBody)
	if err != nil {
		return 0, err
	}
	if len(apiversion) > 0 {
		// vssservice always needs a version, even if there is no content
		if requrl, err := url.Parse(requesturl); err == nil {
			query := requrl.Query()
			query.Set("api-version", apiversion)
			requrl.RawQuery = query.Encode()
			requesturl = requrl.String()
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, requesturl, buf)
	if err != nil {
		return 0, err
	}
	header := request.Header
	contentTypeHeader := http.CanonicalHeaderKey("Content-Type")
	acceptHeader := http.CanonicalHeaderKey("Accept")
	if len(reqContentType) > 0 {
		header[contentTypeHeader] = reqContentType
	}
	if responseBody != nil {
		if _, ok := responseBody.(*[]byte); ok {
			header.Set(acceptHeader, "application/octet-stream")
		} else {
			header.Set(acceptHeader, "application/json")
		}
	}
	if len(apiversion) > 0 {
		// vssservice does only accept contenttype in a single line
		if len(header[contentTypeHeader]) > 0 {
			header[contentTypeHeader][0] += "; api-version=" + apiversion
		}
		if len(header[acceptHeader]) > 0 {
			header[acceptHeader][0] += "; api-version=" + apiversion
		}
		header["X-VSS-E2EID"] = []string{uuid.NewString()}
		header["X-TFS-FedAuthRedirect"] = []string{"Suppress"}
		header["X-TFS-Session"] = []string{uuid.NewString()}
	}
	if len(vssConnection.Token) > 0 {
		header["Authorization"] = []string{"bearer " + vssConnection.Token}
	}
	if vssConnection.Trace {
		fmt.Printf("Http %v Request started %v\nHeaders:\n%v\nBody: `%v`\n", method, requesturl, getHeadersAsString(request.Header), getBodyAsString(buf))
	}

	response, err := vssConnection.HttpClient().Do(request)
	if err != nil {
		return 0, err
	}
	if response == nil {
		return 0, fmt.Errorf("failed to send request response is nil")
	}
	defer response.Body.Close()
	var rbytes []byte
	var responseReader io.Reader
	failed := response.StatusCode < 200 || response.StatusCode >= 300
	readResponse := vssConnection.Trace || failed
	if responseBody != nil {
		responseReader = response.Body
		if readResponse {
			rbytes, err = ioutil.ReadAll(response.Body)
			responseReader = bytes.NewReader(rbytes)
			if err != nil {
				rbytes = []byte("no response: " + err.Error())
			}
		}
	}
	traceMessage := fmt.Sprintf("Http %v Request finished %v %v\nHeaders: \n%v\nBody: `%v`\n", method, response.StatusCode, requesturl, getHeadersAsString(response.Header), string(rbytes))
	if vssConnection.Trace {
		fmt.Print(traceMessage)
	}
	if failed {
		return response.StatusCode, fmt.Errorf("http failure: %v", traceMessage)
	}
	if response.StatusCode != 200 && responseBody != nil {
		return response.StatusCode, io.EOF
	}
	return response.StatusCode, setResponseBody(responseReader, responseBody)
}

func (vssConnection *VssConnection) RequestWithContext2(ctx context.Context, method string, url string, protocol string, requestBody interface{}, responseBody interface{}) error {
	statusCode, err := vssConnection.requestWithContextNoAuth(ctx, method, url, protocol, requestBody, responseBody)
	if (statusCode == 401 || statusCode == 400) && vssConnection.TaskAgent != nil && vssConnection.Key != nil {
		authResponse, err := vssConnection.authorize()
		if err != nil {
			return err
		}
		vssConnection.Token = authResponse.AccessToken
		_, err = vssConnection.requestWithContextNoAuth(ctx, method, url, protocol, requestBody, responseBody)
		return err
	}
	return err
}

func (vssConnection *VssConnection) GetAgentPools() (*TaskAgentPools, error) {
	_taskAgentPools := &TaskAgentPools{}
	if err := vssConnection.Request("a8c47e17-4d56-4a56-92bb-de7ea7dc65be", "", "GET", map[string]string{}, map[string]string{}, nil, _taskAgentPools); err != nil {
		return nil, err
	}
	return _taskAgentPools, nil
}
func (vssConnection *VssConnection) CreateSession(ctx context.Context) (*AgentMessageConnection, error) {
	session := &TaskAgentSession{}
	session.Agent = *vssConnection.TaskAgent
	session.UseFipsEncryption = false // Have to be set to false for "GitHub Enterprise Server 3.0.11", github.com reset it to false 24-07-2021
	session.OwnerName = "RUNNER"
	if err := vssConnection.RequestWithContext(ctx, "134e239e-2df3-4794-a6f6-24f1f19ec8dc", "5.1-preview", "POST", map[string]string{
		"poolId": fmt.Sprint(vssConnection.PoolID),
	}, map[string]string{}, session, session); err != nil {
		return nil, err
	}

	con := &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}
	var err error
	con.Block, err = con.TaskAgentSession.GetSessionKey(vssConnection.Key)
	if err != nil {
		_ = con.Delete(ctx)
		return nil, err
	}
	return con, nil
}

func (vssConnection *VssConnection) LoadSession(ctx context.Context, session *TaskAgentSession) (*AgentMessageConnection, error) {
	con := &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}
	var err error
	con.Block, err = con.TaskAgentSession.GetSessionKey(vssConnection.Key)
	if err != nil {
		_ = con.Delete(ctx)
		return nil, err
	}
	return con, nil
}

func (vssConnection *VssConnection) UpdateTimeLine(timelineID string, jobreq *AgentJobRequestMessage, wrap *TimelineRecordWrapper) error {
	return vssConnection.Request("8893bc5b-35b2-4be7-83cb-99e683551db4", "5.1-preview", "PATCH", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanID,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineID,
	}, map[string]string{}, wrap, nil)
}

func (vssConnection *VssConnection) UploadLogFile(timelineID string, jobreq *AgentJobRequestMessage, logContent string) (int, error) {
	log := &TaskLog{}
	p := "logs/" + uuid.NewString()
	log.Path = &p
	log.CreatedOn = time.Now().UTC().Format(TimestampOutputFormat)
	log.LastChangedOn = time.Now().UTC().Format(TimestampOutputFormat)

	err := vssConnection.Request("46f5667d-263a-4684-91b1-dff7fdcf64e2", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanID,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineID,
	}, map[string]string{}, log, log)
	if err != nil {
		return 0, err
	}
	err = vssConnection.Request("46f5667d-263a-4684-91b1-dff7fdcf64e2", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": jobreq.Plan.ScopeIdentifier,
		"planId":          jobreq.Plan.PlanID,
		"hubName":         jobreq.Plan.PlanType,
		"timelineId":      timelineID,
		"logId":           fmt.Sprint(log.ID),
	}, map[string]string{}, bytes.NewBufferString(logContent), nil)
	return log.ID, err
}

func (vssConnection *VssConnection) DeleteAgent(taskAgent *TaskAgent) error {
	return vssConnection.Request("e298ef32-5878-4cab-993c-043836571f42", "6.0-preview.2", "DELETE", map[string]string{
		"poolId":  fmt.Sprint(vssConnection.PoolID),
		"agentId": fmt.Sprint(taskAgent.ID),
	}, map[string]string{}, nil, nil)
}

func (vssConnection *VssConnection) FinishJob(e *JobEvent, plan *TaskOrchestrationPlanReference) error {
	return vssConnection.Request("557624af-b29e-4c20-8ab0-0399d2204f3f", "2.0-preview.1", "POST", map[string]string{
		"scopeIdentifier": plan.ScopeIdentifier,
		"planId":          plan.PlanID,
		"hubName":         plan.PlanType,
	}, map[string]string{}, e, nil)
}

func (vssConnection *VssConnection) SendLogLines(plan *TaskOrchestrationPlanReference, timelineID string, lines *TimelineRecordFeedLinesWrapper) error {
	return vssConnection.Request("858983e4-19bd-4c5e-864c-507b59b58b12", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": plan.ScopeIdentifier,
		"planId":          plan.PlanID,
		"hubName":         plan.PlanType,
		"timelineId":      timelineID,
		"recordId":        lines.StepID,
	}, map[string]string{}, lines, nil)
}
