package compat

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalConfig(t *testing.T) {
	table := []struct {
		name     string
		jsonData string
		expected DotnetAgent
	}{
		{
			name:     "Boolean true without quotes",
			jsonData: `{"UseV2Flow": true}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(true)},
		},
		{
			name:     "Boolean false without quotes",
			jsonData: `{"UseV2Flow": false}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(false)},
		},
		{
			name:     "Boolean false without quotes no space",
			jsonData: `{"UseV2Flow":false}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(false)},
		},
		{
			name:     "Boolean True with quotes",
			jsonData: `{"UseV2Flow": "True"}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(true)},
		},
		{
			name:     "Boolean False with quotes",
			jsonData: `{"UseV2Flow": "False"}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(false)},
		},
		{
			name:     "Boolean true with quotes",
			jsonData: `{"UseV2Flow": "true"}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(true)},
		},
		{
			name:     "Boolean false with quotes",
			jsonData: `{"UseV2Flow": "false"}`,
			expected: DotnetAgent{UseV2Flow: DotnetBoolean(false)},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var agent DotnetAgent
			err := json.Unmarshal([]byte(tt.jsonData), &agent)
			if err != nil {
				t.Fatalf("Unexpected error during unmarshal: %v", err)
			}
			if agent.UseV2Flow != tt.expected.UseV2Flow {
				t.Errorf("Expected UseV2Flow to be %v, got %v", tt.expected.UseV2Flow, agent.UseV2Flow)
			}
		})
	}
}

func TestMarshalDotnetBoolean(t *testing.T) {
	table := []struct {
		name         string
		agent        DotnetBoolean
		expectedJSON string
	}{
		{
			name:         "Boolean true",
			agent:        DotnetBoolean(true),
			expectedJSON: "true",
		},
		{
			name:         "Boolean false",
			agent:        DotnetBoolean(false),
			expectedJSON: "false",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.agent)
			if err != nil {
				t.Fatalf("Unexpected error during marshal: %v", err)
			}
			if string(data) != tt.expectedJSON {
				t.Errorf("Expected JSON to be %s, got %s", tt.expectedJSON, string(data))
			}
		})
	}
}
