package runneradmin

type Authorization struct {
	AuthorizationURL string `json:"authorization_url"`
	ServerURL        string `json:"server_url"`
	ClientID         string `json:"client_id"`
}

type Runner struct {
	Name          string        `json:"name"`
	ID            int32         `json:"id"`
	Authorization Authorization `json:"authorization"`
}

type RunnerGroup struct {
	ID        int32  `json:"id,omitempty"`
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
