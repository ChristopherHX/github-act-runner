// +build !linux,!darwin,!windows,!openbsd,!netbsd,!freebsd

package main

import (
	"fmt"
)

func RunnerGroupSurvey(taskAgentPool string, taskAgentPools []string) string {
	fmt.Printf("Survey disabled, due to incompatibility with some platforms:\nAvailable runner groups are [%v] using %v", taskAgentPools, taskAgentPool)
	return taskAgentPool
}

func GetInput(prompt string, answer string) string {
	fmt.Println("Survey disabled, due to incompatibility with some platforms:\nFailed to retrieve your choice using default: " + answer)
	return answer
}
