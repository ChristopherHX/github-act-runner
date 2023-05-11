//go:build !linux && !darwin && !windows && !openbsd && !netbsd && !freebsd
// +build !linux,!darwin,!windows,!openbsd,!netbsd,!freebsd

package main

import (
	"fmt"
)

func RunnerGroupSurvey(taskAgentPool string, taskAgentPools []string) string {
	fmt.Printf("Survey disabled, due to incompatibility with some platforms:\nAvailable runner groups are [%v] using %v\n", taskAgentPools, taskAgentPool)
	return taskAgentPool
}

func GetInput(prompt string, answer string) string {
	fmt.Printf("Survey disabled, due to incompatibility with some platforms: %v\nFailed to retrieve your choice using default: %v\n", prompt, answer)
	return answer
}

func GetMultiSelectInput(prompt string, options []string) []string {
	fmt.Printf("Survey disabled, due to incompatibility with some platforms: %v\nFailed to retrieve your choice selecting all: %v\n", prompt, options)
	return options
}
