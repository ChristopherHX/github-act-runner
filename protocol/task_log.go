package protocol

type TaskLogReference struct {
	ID       int
	Location *string
}

type TaskLog struct {
	TaskLogReference
	IndexLocation *string `json:",omitempty"`
	Path          *string `json:",omitempty"`
	LineCount     *int64  `json:",omitempty"`
	CreatedOn     string
	LastChangedOn string
}
