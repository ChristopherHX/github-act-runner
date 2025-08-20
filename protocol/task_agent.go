package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// Just a convenient way to store the URL, not part of the spec
	ServerV2URL string `json:",omitempty"`
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
