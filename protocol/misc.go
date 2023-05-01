package protocol

import (
	"fmt"
	"strings"
)

type RunnerAddRemove struct {
	URL         string `json:"url"`
	RunnerEvent string `json:"runner_event"`
}

type GitHubRunnerRegisterToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type GitHubAuthResult struct {
	TenantURL   string `json:"url"`
	TokenSchema string `json:"token_schema"`
	Token       string `json:"token"`
}

type TaskOrchestrationPlanReference struct {
	ScopeIdentifier string
	PlanID          string
	PlanType        string
	Version         int32
}

type JobAuthorization struct {
	Parameters map[string]string
	Scheme     string
}

type JobEndpoint struct {
	Data          map[string]string
	Name          string
	URL           string
	Authorization JobAuthorization
	IsShared      bool
	IsReady       bool
}

type JobResources struct {
	Endpoints []JobEndpoint
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
	URL  *string `json:",omitempty"`
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
	ID               string
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
	JobID                string
	JobDisplayName       string
	JobName              string
	JobContainer         *TemplateToken
	JobServiceContainers *TemplateToken
	JobOutputs           *TemplateToken
	RequestID            int64
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

func (jobreq *AgentJobRequestMessage) GetConnection(name string) (*VssConnection, map[string]string, error) {
	if jobreq.Resources == nil {
		return nil, nil, fmt.Errorf("missing resources")
	}
	if jobreq.Resources.Endpoints == nil {
		return nil, nil, fmt.Errorf("missing resources.endpoints")
	}
	for _, endpoint := range jobreq.Resources.Endpoints {
		if strings.EqualFold(endpoint.Name, name) {
			con := &VssConnection{
				TenantURL: endpoint.URL,
			}
			if endpoint.Authorization.Parameters != nil {
				con.Token = endpoint.Authorization.Parameters["AccessToken"]
			}
			return con, endpoint.Data, nil
		}
	}
	return nil, nil, fmt.Errorf("no connection with name '%v' found", name)
}

type RenewAgent struct {
	RequestID int64
}

type VssOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

var TimestampInputFormat = "2006-01-02T15:04:05.9999999Z07:00"  // allow to omit fractional seconds
var TimestampOutputFormat = "2006-01-02T15:04:05.0000000Z07:00" // dotnet "O"
