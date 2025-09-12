package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

const (
	// JWT token expiration time
	jwtExpiration = 5 * time.Minute

	// Error message prefix for authorization failures
	authFailurePrefix = "Failed to Authorize: "
)

type TaskAgentPublicKey struct {
	Exponent string
	Modulus  string
}

type TaskAgentAuthorization struct {
	AuthorizationURL string `json:",omitempty"`
	ClientID         string `json:",omitempty"`
	PublicKey        TaskAgentPublicKey
}

type AgentLabel struct {
	ID   int
	Name string
	Type string
}

type PropertyValue struct {
	Type  string      `json:"$type"`
	Value interface{} `json:"$value"`
}

func (v *PropertyValue) UnmarshalJSON(data []byte) error {
	var b bool
	if json.Unmarshal(data, &b) == nil {
		v.Type = "System.Boolean"
		v.Value = b
		return nil
	}
	var raw string
	if json.Unmarshal(data, &raw) == nil {
		v.Type = "System.String"
		v.Value = raw
		return nil
	}
	type PropertyValueRaw PropertyValue
	// Best Effort, drop errors
	_ = json.Unmarshal(data, (*PropertyValueRaw)(v))
	return nil
}

type PropertiesCollection map[string]PropertyValue

func (c *PropertiesCollection) Lookup(name, ty string) (interface{}, bool) {
	for k, v := range *c {
		if strings.EqualFold(k, name) && strings.EqualFold(v.Type, ty) {
			return v.Value, true
		}
	}
	return nil, false
}

func (c *PropertiesCollection) LookupBool(name string) (value, ok bool) {
	if v, ok := c.Lookup(name, "System.Boolean"); ok && v != nil {
		b, isBool := v.(bool)
		return b, isBool
	}
	return false, false
}

func (c *PropertiesCollection) LookupString(name string) (string, bool) {
	if v, ok := c.Lookup(name, "System.String"); ok && v != nil {
		b, isString := v.(string)
		return b, isString
	}
	return "", false
}

type TaskAgent struct {
	Authorization     TaskAgentAuthorization
	Labels            []AgentLabel
	MaxParallelism    int
	ID                int64
	Name              string
	Version           string
	OSDescription     string
	Enabled           *bool `json:",omitempty"`
	ProvisioningState string
	AccessPoint       string `json:",omitempty"`
	CreatedOn         string
	Ephemeral         bool `json:",omitempty"`
	DisableUpdate     bool `json:",omitempty"`
	Properties        PropertiesCollection
}

type TaskAgents struct {
	Count int64
	Value []TaskAgent
}

func (taskAgent *TaskAgent) Authorize(c *http.Client, key interface{}) (*VssOAuthTokenResponse, error) {
	tokenresp := &VssOAuthTokenResponse{}
	now := time.Now().UTC().Add(-30 * time.Second)
	token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   taskAgent.Authorization.ClientID,
		Issuer:    taskAgent.Authorization.ClientID,
		Id:        uuid.New().String(),
		Audience:  taskAgent.Authorization.AuthorizationURL,
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(jwtExpiration).Unix(),
	})
	stkn, err := token2.SignedString(key)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", stkn)
	data.Set("grant_type", "client_credentials")

	//nolint:noctx // Legacy function without context - would break API compatibility
	poolsreq, err := http.NewRequest(http.MethodPost, taskAgent.Authorization.AuthorizationURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, errors.New(authFailurePrefix + err.Error())
	}
	poolsreq.Header["Content-Type"] = []string{"application/x-www-form-urlencoded; charset=utf-8"}
	poolsreq.Header["Accept"] = []string{"application/json"}
	poolsresp, err := c.Do(poolsreq)
	if err != nil {
		return nil, errors.New(authFailurePrefix + err.Error())
	}
	defer func() {
		_ = poolsresp.Body.Close() // Ignore close error
	}()
	if poolsresp.StatusCode != http.StatusOK {
		responseBytes, _ := io.ReadAll(poolsresp.Body)
		return nil, errors.New("Failed to Authorize, service responded with code " + fmt.Sprint(poolsresp.StatusCode) +
			": " + string(responseBytes))
	}
	dec := json.NewDecoder(poolsresp.Body)
	if err := dec.Decode(tokenresp); err != nil {
		return nil, err
	}
	return tokenresp, nil
}
