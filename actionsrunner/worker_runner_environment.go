package actionsrunner

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

const (
	// Binary protocol constants
	messageIDSize    = 4
	cancelRequestCmd = 2
	// File permissions
	filePermissions = 0o664
)

type WorkerRunnerEnvironment struct {
	WorkerArgs []string
}

func (arunner *WorkerRunnerEnvironment) WriteJSON(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, filePermissions)
}

func (arunner *WorkerRunnerEnvironment) ReadJSON(path string, value interface{}) error {
	//nolint:gosec // Path is provided by worker configuration, not user input
	cont, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(cont, value)
}

func (arunner *WorkerRunnerEnvironment) Remove(fname string) error {
	return os.Remove(fname)
}

func (arunner *WorkerRunnerEnvironment) Printf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (arunner *WorkerRunnerEnvironment) ExecWorker(
	_ *RunRunner, wc WorkerContext, _ *protocol.AgentJobRequestMessage, src []byte,
) error {
	jlogger := wc.Logger()
	jobExecCtx := wc.JobExecCtx()
	if len(arunner.WorkerArgs) == 0 {
		return fmt.Errorf("missing WorkerArgs to execute an external worker")
	}
	//nolint:gosec // WorkerArgs are configured by the administrator, not user input
	worker := exec.CommandContext(jobExecCtx, arunner.WorkerArgs[0], arunner.WorkerArgs[1:]...)
	in, err := worker.StdinPipe()
	if err != nil {
		return err
	}
	er, err := worker.StderrPipe()
	if err != nil {
		return err
	}
	out, err := worker.StdoutPipe()
	if err != nil {
		return err
	}
	err = worker.Start()
	if err != nil {
		return err
	}
	_ = jlogger.Logger.Close() // Ignore logger close errors
	jlogger.Current().Complete("Succeeded")
	jlogger.MoveNext()
	mid := make([]byte, messageIDSize)
	binary.BigEndian.PutUint32(mid, 1) // NewJobRequest
	_, err = in.Write(mid)
	if err != nil {
		fmt.Printf("failed to write new job: %s", err)
	}
	binary.BigEndian.PutUint32(mid, uint32(len(src))) //nolint:gosec
	_, err = in.Write(mid)
	if err != nil {
		fmt.Printf("failed to write new job: %s", err)
	}
	_, err = in.Write(src)
	if err != nil {
		fmt.Printf("failed to write new job: %s", err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-jobExecCtx.Done():
			binary.BigEndian.PutUint32(mid, cancelRequestCmd) // CancelRequest
			_, err = in.Write(mid)
			if err != nil {
				fmt.Printf("failed to write cancel job: %s", err)
			}
			binary.BigEndian.PutUint32(mid, uint32(len(src))) //nolint:gosec
			_, err = in.Write(mid)
			if err != nil {
				fmt.Printf("failed to write cancel job length: %s", err)
			}
			_, err = in.Write(src)
			if err != nil {
				fmt.Printf("failed to write cancel job body: %s", err)
			}
		case <-done:
		}
	}()
	_, err = io.Copy(os.Stdout, out)
	if err != nil {
		fmt.Printf("failed to copy out to stdout: %s", err)
	}
	_, err = io.Copy(os.Stdout, er)
	if err != nil {
		fmt.Printf("failed to copy err to stdout: %s", err)
	}
	_ = worker.Wait() // Ignore wait errors, checked with ProcessState
	if exitcode := worker.ProcessState.ExitCode(); exitcode != 0 {
		return fmt.Errorf("failed to execute worker: %v", exitcode)
	}
	return nil
}
