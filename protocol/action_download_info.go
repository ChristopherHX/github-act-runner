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
	Authentication        ActionDownloadAuthentication
	NameWithOwner         string
	ResolvedNameWithOwner string
	ResolvedSha           string
	TarballUrl            string
	Ref                   string
	ZipballUrl            string
}

type ActionDownloadAuthentication struct {
	ExpiresAt string
	Token     string
}
