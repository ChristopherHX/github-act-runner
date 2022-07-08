package runnerconfiguration

type Survey interface {
	GetInput(prompt string, def string) string
	GetSelectInput(prompt string, options []string, def string) string
	GetMultiSelectInput(prompt string, options []string) []string
}
