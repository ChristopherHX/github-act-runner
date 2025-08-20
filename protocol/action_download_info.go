package protocol

type ActionReferenceList struct {
	Actions []ActionReference
}

type ActionReference struct {
	NameWithOwner string
	Ref           string
	Path          string
}

type ActionDownloadInfoCollection struct {
	Actions map[string]ActionDownloadInfo
}

type ActionDownloadInfo struct {
	Authentication        *ActionDownloadAuthentication `json:",omitempty"`
	NameWithOwner         string
	ResolvedNameWithOwner string
	ResolvedSha           string
	TarballURL            string
	Ref                   string
	ZipballURL            string
}

type ActionDownloadAuthentication struct {
	ExpiresAt string `json:",omitempty"`
	Token     string
}
