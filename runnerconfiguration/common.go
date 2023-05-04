package runnerconfiguration

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
}

type RunnerSettings struct {
	PoolID          int64
	RegistrationURL string
	Instances       []*RunnerInstance
}

func gitHubAuth(config *ConfigureRemoveRunner, c *http.Client, runnerEvent string, apiEndpoint string, survey Survey) (*protocol.GitHubAuthResult, error) {
	registerUrl, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Url: %v\n", config.URL)
	}
	apiscope := "/"
	if strings.ToLower(registerUrl.Host) == "github.com" {
		registerUrl.Host = "api." + registerUrl.Host
	} else {
		apiscope = "/api/v3"
	}

	if len(config.Token) == 0 {
		if len(config.Pat) > 0 {
			paths := strings.Split(strings.TrimPrefix(registerUrl.Path, "/"), "/")
			url := *registerUrl
			if len(paths) == 1 {
				url.Path = path.Join(apiscope, "orgs", paths[0], "actions/runners", apiEndpoint)
			} else if len(paths) == 2 {
				scope := "repos"
				if strings.EqualFold(paths[0], "enterprises") {
					scope = ""
				}
				url.Path = path.Join(apiscope, scope, paths[0], paths[1], "actions/runners", apiEndpoint)
			} else {
				return nil, fmt.Errorf("unsupported registration url")
			}
			req, _ := http.NewRequest("POST", url.String(), nil)
			req.SetBasicAuth("github", config.Pat)
			req.Header.Add("Accept", "application/vnd.github.v3+json")
			resp, err := c.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve %v token via pat: %v\n", apiEndpoint, err.Error())
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := ioutil.ReadAll(resp.Body)
				return nil, fmt.Errorf("failed to retrieve %v via pat [%v]: %v\n", apiEndpoint, fmt.Sprint(resp.StatusCode), string(body))
			}
			tokenresp := &protocol.GitHubRunnerRegisterToken{}
			dec := json.NewDecoder(resp.Body)
			if err := dec.Decode(tokenresp); err != nil {
				return nil, fmt.Errorf("failed to decode registration token via pat: " + err.Error())
			}
			config.Token = tokenresp.Token
		} else if !config.Unattended {
			config.Token = survey.GetInput("Please enter your runner registration token:", "")
		}
	}
	if len(config.Token) == 0 {
		return nil, fmt.Errorf("no runner registration token provided")
	}
	registerUrl.Path = path.Join(apiscope, "actions/runner-registration")

	buf := new(bytes.Buffer)
	req := &protocol.RunnerAddRemove{}
	req.URL = config.URL
	req.RunnerEvent = runnerEvent
	enc := json.NewEncoder(buf)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	finalregisterUrl := registerUrl.String()

	r, _ := http.NewRequest("POST", finalregisterUrl, buf)
	r.Header["Authorization"] = []string{"RemoteAuth " + config.Token}
	resp, err := c.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to register Runner: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to register Runner with status code: %v\n", resp.StatusCode)
	}

	res := &protocol.GitHubAuthResult{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(res); err != nil {
		return nil, fmt.Errorf("error decoding struct from JSON: %v\n", err)
	}
	return res, nil
}

func (config *ConfigureRunner) Authenicate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return gitHubAuth(&config.ConfigureRemoveRunner, c, "register", "registration-token", survey)
}
func (config *RemoveRunner) Authenicate(c *http.Client, survey Survey) (*protocol.GitHubAuthResult, error) {
	return gitHubAuth(&config.ConfigureRemoveRunner, c, "remove", "remove-token", survey)
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
