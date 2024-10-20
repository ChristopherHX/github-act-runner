package actionsdotnetactcompat

import (
	"github.com/ChristopherHX/github-act-runner/actionsrunner"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/nektos/act/pkg/runner"
)

type ActRunner struct {
	actionsrunner.WorkerRunnerEnvironment
	ApplyConfig func(config *runner.Config, jobreq *protocol.AgentJobRequestMessage) error
}

func (arunner *ActRunner) ExecWorker(run *actionsrunner.RunRunner, wc actionsrunner.WorkerContext, jobreq *protocol.AgentJobRequestMessage, src []byte) error {
	if len(arunner.WorkerArgs) <= 0 {
		ExecWorker(jobreq, wc)
		return nil
	}
	return arunner.WorkerRunnerEnvironment.ExecWorker(run, wc, jobreq, src)
}

func (arunner *ActRunner) callApplyConfig(config *runner.Config, jobreq *protocol.AgentJobRequestMessage) error {
	if arunner.ApplyConfig != nil {
		return arunner.ApplyConfig(config, jobreq)
	}
	return nil
}
