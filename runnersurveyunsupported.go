// +build !linux,!darwin,!windows,!openbsd,!netbsd,!freebsd

package main

import (
	"fmt"
)

func RunnerGroupSurvey(taskAgentPool string, taskAgentPools []string) string {
	fmt.Printf("Survey disabled, due to incompatibility with some platforms:\nAvailable runner groups are [%v] using %v", taskAgentPools, taskAgentPool)
	return taskAgentPool
}
