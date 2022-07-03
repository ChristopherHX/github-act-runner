package protocol

type JobEvent struct {
	Name               string
	JobID              string
	RequestID          int64
	Result             string
	Outputs            *map[string]VariableValue    `json:",omitempty"`
	ActionsEnvironment *ActionsEnvironmentReference `json:",omitempty"`
}
