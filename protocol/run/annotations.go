package run

type AnnotationLevel string

const (
	UNKNOWN AnnotationLevel = "UNKNOWN"
	NOTICE  AnnotationLevel = "NOTICE"
	WARNING AnnotationLevel = "WARNING"
	FAILURE AnnotationLevel = "FAILURE"
)

type Annotation struct {
	Level                 AnnotationLevel `json:"level"`
	Message               string          `json:"message"`
	RawDetails            string          `json:"rawDetails"`
	Path                  string          `json:"path"`
	IsInfrastructureIssue bool            `json:"isInfrastructureIssue"`
	StartLine             int64           `json:"startLine"`
	EndLine               int64           `json:"endLine"`
	StartColumn           int64           `json:"startColumn"`
	EndColumn             int64           `json:"endColumn"`
}
