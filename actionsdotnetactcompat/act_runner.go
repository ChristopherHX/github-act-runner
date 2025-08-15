package actionsdotnetactcompat

import (
	"github.com/ChristopherHX/github-act-runner/actionsrunner"
	"github.com/ChristopherHX/github-act-runner/protocol"
)

type ActRunner struct {
	actionsrunner.WorkerRunnerEnvironment
}

func (arunner *ActRunner) ExecWorker(run *actionsrunner.RunRunner, wc actionsrunner.WorkerContext,
	jobreq *protocol.AgentJobRequestMessage, src []byte,
) error {
	if len(arunner.WorkerArgs) == 0 {
		ExecWorker(jobreq, wc)
		return nil
	}
	return arunner.WorkerRunnerEnvironment.ExecWorker(run, wc, jobreq, src)
}
