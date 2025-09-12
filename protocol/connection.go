package protocol

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ChristopherHX/github-act-runner/common"
)

const (
	apiVersionSuffix = "; api-version="
	statusOnline     = "Online"

	maxIdleConnections = 1
	maxRedirects       = 10

	requestTimeout        = 1 * time.Minute
	idleConnectionTimeout = 100 * time.Second
	httpClientTimeout     = 100 * time.Second
	maxRetryTime          = 600 * time.Second
)

type VssConnection struct {
	Client         *http.Client
	TenantURL      string
	connectionData *ConnectionData
	Token          string
	AuthHeader     string
	PoolID         int64
	TaskAgent      *TaskAgent
	Key            *rsa.PrivateKey
	Trace          bool
}

func (vssConnection *VssConnection) BuildURL(relativePath string, ppath, query map[string]string) (string, error) {
	url2, err := url.Parse(vssConnection.TenantURL)
	if err != nil {
		return "", err
	}
	urlPath := relativePath
	re := regexp.MustCompile(`/*\{[^\}]+\}`)
	urlPath = re.ReplaceAllStringFunc(urlPath, func(s string) string {
		start := strings.Index(s, "{")
		end := strings.Index(s, "}")
		if val, ok := ppath[s[start+1:end]]; ok {
			return s[0:start] + val
		}
		return ""
	})
	url2.Path = path.Join(url2.Path, urlPath)
	q := url2.Query()
	for p, v := range query {
		q.Add(p, v)
	}
	url2.RawQuery = q.Encode()
	return url2.String(), nil
}

func (vssConnection *VssConnection) HTTPClient() *http.Client {
	if vssConnection.Client == nil {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.MaxIdleConns = maxIdleConnections
		customTransport.IdleConnTimeout = idleConnectionTimeout
		if v, ok := common.LookupEnvBool("SKIP_TLS_CERT_VALIDATION"); ok && v {
			//nolint:gosec // Intentionally allows insecure TLS when explicitly configured
			customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		vssConnection.Client = &http.Client{
			Timeout:   httpClientTimeout,
			Transport: customTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				return nil
			},
		}
	}
	return vssConnection.Client
}

func (vssConnection *VssConnection) authorize() (*VssOAuthTokenResponse, error) {
	var authResponse *VssOAuthTokenResponse
	var err error
	authResponse, err = vssConnection.TaskAgent.Authorize(vssConnection.HTTPClient(), vssConnection.Key)
	if err == nil {
		return authResponse, nil
	}
	return nil, err
}

func (vssConnection *VssConnection) Request(
	serviceID, protocol, method string, urlParameter, queryParameter map[string]string, requestBody, responseBody interface{},
) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return vssConnection.RequestWithContext(ctx, serviceID, protocol, method, urlParameter, queryParameter, requestBody, responseBody)
}

func (vssConnection *VssConnection) GetServiceURL(
	ctx context.Context, serviceID string, urlParameter, queryParameter map[string]string,
) (string, error) {
	if vssConnection.connectionData == nil {
		for i := 1; ; {
			vssConnection.connectionData = vssConnection.GetConnectionData()
			if vssConnection.connectionData != nil {
				break
			}
			maxtimeSeconds := int(maxRetryTime / time.Second)
			dtime := time.Duration(i) * time.Second
			if i < maxtimeSeconds {
				i *= 2
			} else {
				dtime = maxRetryTime
			}
			fmt.Printf("Retry retrieving connectiondata from the server in %v seconds\n", dtime/time.Second)
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

func (vssConnection *VssConnection) RequestWithContext(
	ctx context.Context,
	serviceID, protocol, method string,
	urlParameter, queryParameter map[string]string,
	requestBody, responseBody interface{},
) error {
	requestURL, err := vssConnection.GetServiceURL(ctx, serviceID, urlParameter, queryParameter)
	if err != nil {
		return err
	}
	return vssConnection.RequestWithContext2(ctx, method, requestURL, protocol, requestBody, responseBody)
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
		*bresponse, err = io.ReadAll(r)
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

func (vssConnection *VssConnection) requestWithContextNoAuth(
	ctx context.Context, method, requesturl, apiversion string, requestBody, responseBody interface{},
) (int, error) {
	buf, reqContentType, err := extractReader(requestBody)
	if err != nil {
		return 0, err
	}
	if apiversion != "" {
		// vssservice always needs a version, even if there is no content
		if parsedURL, parseErr := url.Parse(requesturl); parseErr == nil {
			query := parsedURL.Query()
			query.Set("api-version", apiversion)
			parsedURL.RawQuery = query.Encode()
			requesturl = parsedURL.String()
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
	header["User-Agent"] = []string{"github-act-runner/v0.11.0"}
	if apiversion != "" {
		// vssservice does only accept contenttype in a single line
		if len(header[contentTypeHeader]) > 0 {
			header[contentTypeHeader][0] += apiVersionSuffix + apiversion
		}
		if len(header[acceptHeader]) > 0 {
			header[acceptHeader][0] += apiVersionSuffix + apiversion
		}
		header["X-VSS-E2EID"] = []string{uuid.NewString()}
		header["X-TFS-FedAuthRedirect"] = []string{"Suppress"}
		header["X-TFS-Session"] = []string{uuid.NewString()}
	}
	if vssConnection.Token != "" {
		header["Authorization"] = []string{"bearer " + vssConnection.Token}
	} else if vssConnection.AuthHeader != "" {
		header["Authorization"] = []string{vssConnection.AuthHeader}
	}
	if vssConnection.Trace {
		fmt.Printf("Http %v Request started %v\nHeaders:\n%v\nBody: `%v`\n",
			method, requesturl, getHeadersAsString(request.Header), getBodyAsString(buf))
	}

	response, err := vssConnection.HTTPClient().Do(request)
	if err != nil {
		return 0, err
	}
	if response == nil {
		return 0, fmt.Errorf("failed to send request response is nil")
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			fmt.Printf("Failed to close response body: %v", closeErr)
		}
	}()
	var rbytes []byte
	var responseReader io.Reader
	failed := response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices
	readResponse := vssConnection.Trace || failed
	if responseBody != nil {
		responseReader = response.Body
		if readResponse {
			rbytes, err = io.ReadAll(response.Body)
			responseReader = bytes.NewReader(rbytes)
			if err != nil {
				rbytes = []byte("no response: " + err.Error())
			}
		}
	}
	traceMessage := fmt.Sprintf(
		"Http %v Request finished %v %v\nHeaders: \n%v\nBody: `%v`\n",
		method, response.StatusCode, requesturl,
		getHeadersAsString(response.Header), string(rbytes))
	if vssConnection.Trace {
		fmt.Print(traceMessage)
	}
	if failed {
		return response.StatusCode, fmt.Errorf("http failure: %v", traceMessage)
	}
	if response.StatusCode == http.StatusNoContent && responseBody != nil {
		return response.StatusCode, io.EOF
	}
	return response.StatusCode, setResponseBody(responseReader, responseBody)
}

func (vssConnection *VssConnection) RequestWithContext2(
	ctx context.Context, method, requestURL, protocol string, requestBody, responseBody interface{},
) error {
	statusCode, err := vssConnection.requestWithContextNoAuth(ctx, method, requestURL, protocol, requestBody, responseBody)
	if (statusCode == 401 || statusCode == 400) && vssConnection.TaskAgent != nil && vssConnection.Key != nil {
		authResponse, authErr := vssConnection.authorize()
		if authErr != nil {
			return authErr
		}
		vssConnection.Token = authResponse.AccessToken
		_, err = vssConnection.requestWithContextNoAuth(ctx, method, requestURL, protocol, requestBody, responseBody)
		return err
	}
	return err
}

func (vssConnection *VssConnection) GetAgentPools() (*TaskAgentPools, error) {
	_taskAgentPools := &TaskAgentPools{}
	err := vssConnection.Request(
		"a8c47e17-4d56-4a56-92bb-de7ea7dc65be", "", "GET",
		map[string]string{}, map[string]string{}, nil, _taskAgentPools)
	if err != nil {
		return nil, err
	}
	return _taskAgentPools, nil
}

func (vssConnection *VssConnection) CreateSessionExt(ctx context.Context, serverV2URL string) (*AgentMessageConnection, error) {
	session := &TaskAgentSession{}
	session.Agent = *vssConnection.TaskAgent
	session.UseFipsEncryption = false // Have to be set to false for "GitHub Enterprise Server 3.0.11", github.com reset it to false 24-07-2021
	session.OwnerName = "RUNNER"
	if serverV2URL != "" {
		err := vssConnection.RequestWithContext2(ctx, "POST", serverV2URL+"/session", "", session, session)
		if err != nil {
			return nil, err
		}
	} else {
		if err := vssConnection.RequestWithContext(ctx, "134e239e-2df3-4794-a6f6-24f1f19ec8dc", "5.1-preview", "POST", map[string]string{
			"poolId": fmt.Sprint(vssConnection.PoolID),
		}, map[string]string{}, session, session); err != nil {
			return nil, err
		}
		if session.BrokerMigrationMessage != nil {
			return vssConnection.CreateSessionExt(ctx, session.BrokerMigrationMessage.BrokerBaseURL)
		}
	}

	con := &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}
	con.Status = statusOnline
	con.ServerV2URL = serverV2URL
	return con, nil
}

func (vssConnection *VssConnection) CreateSession(ctx context.Context) (*AgentMessageConnection, error) {
	useV2Flow, hasUseV2Flow := vssConnection.TaskAgent.Properties.LookupBool("UseV2Flow")
	serverV2URL, hasServerV2URL := vssConnection.TaskAgent.Properties.LookupString("ServerUrlV2")
	if !useV2Flow || !hasUseV2Flow || !hasServerV2URL {
		serverV2URL = ""
	} else {
		serverV2URL = strings.TrimSuffix(serverV2URL, "/")
	}
	return vssConnection.CreateSessionExt(ctx, serverV2URL)
}

func (vssConnection *VssConnection) LoadSession(ctx context.Context, session *TaskAgentSession) (*AgentMessageConnection, error) {
	con := &AgentMessageConnection{VssConnection: vssConnection, TaskAgentSession: session}
	con.Status = statusOnline
	useV2Flow, hasUseV2Flow := vssConnection.TaskAgent.Properties.LookupBool("UseV2Flow")
	serverV2URL, hasServerV2URL := vssConnection.TaskAgent.Properties.LookupString("ServerUrlV2")
	if !useV2Flow || !hasUseV2Flow || !hasServerV2URL {
		serverV2URL = ""
	} else {
		serverV2URL = strings.TrimSuffix(serverV2URL, "/")
	}
	con.ServerV2URL = serverV2URL
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

func (vssConnection *VssConnection) SendLogLines(
	plan *TaskOrchestrationPlanReference, timelineID string, lines *TimelineRecordFeedLinesWrapper,
) error {
	return vssConnection.Request("858983e4-19bd-4c5e-864c-507b59b58b12", "5.1-preview", "POST", map[string]string{
		"scopeIdentifier": plan.ScopeIdentifier,
		"planId":          plan.PlanID,
		"hubName":         plan.PlanType,
		"timelineId":      timelineID,
		"recordId":        lines.StepID,
	}, map[string]string{}, lines, nil)
}
