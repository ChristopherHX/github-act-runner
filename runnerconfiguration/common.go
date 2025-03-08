package runnerconfiguration

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
)

type ConfigureRemoveRunner struct {
	Client     *http.Client
	URL        string
	Name       string
	Token      string
	Pat        string
	Unattended bool
	Trace      bool
}

func (c *ConfigureRemoveRunner) GetHttpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	if v, ok := common.LookupEnvBool("SKIP_TLS_CERT_VALIDATION"); ok && v {
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c.Client = &http.Client{
		Timeout:   100 * time.Second,
		Transport: customTransport,
	}
	return c.Client
}

type ConfigureRunner struct {
	ConfigureRemoveRunner
	Labels          []string
	NoDefaultLabels bool
	SystemLabels    []string
	RunnerGroup     string
	Ephemeral       bool
	RunnerGuard     string
	Replace         bool
	DisableUpdate   bool
	WorkFolder      string
}

type RemoveRunner struct {
	ConfigureRemoveRunner
	Force bool
}

type RunnerInstance struct {
	PoolID          int64
	RegistrationURL string
	Auth            *protocol.GitHubAuthResult
	Agent           *protocol.TaskAgent
	Key             string
	PKey            *rsa.PrivateKey `json:"-"`
	RunnerGuard     string
	WorkFolder      string // Currently unused for actions/runner compat
}

func (instance *RunnerInstance) EnshurePKey() error {
	if instance.PKey == nil {
		key, err := base64.StdEncoding.DecodeString(instance.Key)
		if err != nil {
			return err
		}
		pkey, err := x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return err
		}
		instance.PKey = pkey
	}
	return nil
}

type RunnerSettings struct {
	PoolID          int64
	RegistrationURL string
	Instances       []*RunnerInstance
}

type GithubApiUrlBuilder struct {
	URL      *url.URL
	ApiScope string
}

func NewGithubApiUrlBuilder(URL string) (*GithubApiUrlBuilder, error) {
	baseUrl, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	apiBuilder := &GithubApiUrlBuilder{
		URL: baseUrl,
	}
	if strings.EqualFold(apiBuilder.URL.Host, "github.com") || strings.HasSuffix(strings.ToLower(apiBuilder.URL.Host), ".ghe.com") {
		apiBuilder.URL.Host = "api." + apiBuilder.URL.Host
	} else {
		apiBuilder.ApiScope = "/api/v3"
	}
	return apiBuilder, nil
}

func (apiBuilder *GithubApiUrlBuilder) AbsoluteApiUrl(p string) string {
	url := *apiBuilder.URL
	url.Path = path.Join(apiBuilder.ApiScope, p)
	return url.String()
}

func (apiBuilder *GithubApiUrlBuilder) ScopedApiUrl(p string) (string, error) {
	url := *apiBuilder.URL
	paths := strings.Split(strings.TrimPrefix(url.Path, "/"), "/")
	if len(paths) == 1 {
		url.Path = path.Join(apiBuilder.ApiScope, "orgs", paths[0], p)
	} else if len(paths) == 2 {
		scope := "repos"
		if strings.EqualFold(paths[0], "enterprises") {
			scope = ""
		}
		url.Path = path.Join(apiBuilder.ApiScope, scope, paths[0], paths[1], p)
	} else {
		return "", fmt.Errorf("unsupported registration url")
	}
	return url.String(), nil
}

func gitHubAuth(config *ConfigureRemoveRunner, c *http.Client, runnerEvent string, apiEndpoint string, survey Survey) (*protocol.GitHubAuthResult, error) {
	if config.URL == "" && !config.Unattended {
		config.URL = survey.GetInput("Which GitHub Url is assosiated with this runner (Normally this isn't missing):", "")
	}
	apiBuilder, err := NewGithubApiUrlBuilder(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Url: %v", config.URL)
	}
	if len(config.Token) == 0 {
		if len(config.Pat) > 0 {
			url, err := apiBuilder.ScopedApiUrl(path.Join("actions/runners", apiEndpoint))
			if err != nil {
				return nil, err
			}
			client := &protocol.VssConnection{
				AuthHeader: fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte("GitHub:"+config.Pat))),
				Trace:      config.Trace,
				Client:     c,
			}
			tokenresp := &protocol.GitHubRunnerRegisterToken{}
			err = client.RequestWithContext2(context.Background(), "POST", url, "", nil, tokenresp)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve %v token via pat: %v", apiEndpoint, err.Error())
			}
			config.Token = tokenresp.Token
		} else if !config.Unattended {
			config.Token = survey.GetInput("Please enter your runner registration token:", "")
		}
	}
	if len(config.Token) == 0 {
		return nil, fmt.Errorf("no runner registration token provided")
	}

	finalregisterUrl := apiBuilder.AbsoluteApiUrl("actions/runner-registration")

	client := &protocol.VssConnection{
		AuthHeader: "RemoteAuth " + config.Token,
		Trace:      config.Trace,
		Client:     c,
	}
	res := &protocol.GitHubAuthResult{}
	err = client.RequestWithContext2(context.Background(), "POST", finalregisterUrl, "", &protocol.RunnerAddRemove{
		URL:         config.URL,
		RunnerEvent: runnerEvent,
	}, res)

	if err != nil {
		return nil, fmt.Errorf("failed to authenticate as Runner Admin: %v", err)
	}
	return res, nil
}

func (config *ConfigureRunner) Authenticate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return gitHubAuth(&config.ConfigureRemoveRunner, c, "register", "registration-token", survey)
}
func (config *RemoveRunner) Authenticate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return gitHubAuth(&config.ConfigureRemoveRunner, c, "remove", "remove-token", survey)
}

// Deprecated: Use the Authenticate method.
func (config *ConfigureRunner) Authenicate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return config.Authenticate(c, survey)
}

// Deprecated: Use the Authenticate method.
func (config *RemoveRunner) Authenicate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return config.Authenticate(c, survey)
}

func (confremove *ConfigureRemoveRunner) ReadFromEnvironment() {
	if len(confremove.Pat) == 0 {
		if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_PAT"); ok {
			confremove.Pat = v
		}
	}
	if len(confremove.Token) == 0 {
		if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_TOKEN"); ok {
			confremove.Token = v
		}
	}
	if !confremove.Unattended {
		if v, ok := common.LookupEnvBool("ACTIONS_RUNNER_INPUT_UNATTENDED"); ok {
			confremove.Unattended = v
		}
	}
	if len(confremove.URL) == 0 {
		if v, ok := os.LookupEnv("ACTIONS_RUNNER_INPUT_URL"); ok {
			confremove.URL = v
		}
	}
}
