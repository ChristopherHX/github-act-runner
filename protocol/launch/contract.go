package launch

type ActionReferenceRequest struct {
	Action  string `json:"action,omitempty"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

type ActionReferenceRequestList struct {
	Actions []ActionReferenceRequest `json:"actions,omitempty"`
}

type ActionDownloadInfoResponse struct {
	Authentication *ActionDownloadAuthenticationResponse `json:"authentication,omitempty"`
	Name           string                                `json:"name,omitempty"`
	ResolvedName   string                                `json:"resolved_name,omitempty"`
	ResolvedSha    string                                `json:"resolved_sha,omitempty"`
	TarUrl         string                                `json:"tar_url,omitempty"`
	Version        string                                `json:"version,omitempty"`
	ZipUrl         string                                `json:"zip_url,omitempty"`
}

type ActionDownloadAuthenticationResponse struct {
	ExpiresAt string `json:"expires_at,omitempty"`
	Token     string `json:"token,omitempty"`
}

type ActionDownloadInfoResponseCollection struct {
	Actions map[string]ActionDownloadInfoResponse `json:"actions,omitempty"`
}
