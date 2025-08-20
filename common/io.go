package common

import (
	"encoding/json"
	"os"
)

const (
	// File permissions
	filePermissions = 0o664
)

func WriteJSON(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, filePermissions)
}

func ReadJSON(path string, value interface{}) error {
	//nolint:gosec // Path is provided by application configuration, not user input
	cont, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(cont, value)
}
