package runneradmin

type Authorization struct {
	AuthorizationUrl string `json:"authorization_url"`
	ServerUrl        string `json:"server_url"`
	ClientId         string `json:"client_id"`
}

type Runner struct {
	Name          string        `json:"name"`
	Id            int32         `json:"id"`
	Authorization Authorization `json:"authorization"`
}

type RunnerGroup struct {
	Id        int32  `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	IsDefault bool   `json:"default,omitempty"`
	IsHosted  bool   `json:"is_hosted,omitempty"`
}

type RunnerGroupList struct {
	RunnerGroups []RunnerGroup `json:"runner_groups"`
	Count        int           `json:"total_count"`
}

type ListRunnersResponse struct {
	TotalCount int      `json:"total_count"`
	Runners    []Runner `json:"runners"`
}
