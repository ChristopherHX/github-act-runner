package actionsrunner

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

type WorkerRunnerEnvironment struct {
	WorkerArgs []string
}

func (arunner *WorkerRunnerEnvironment) WriteJson(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, 0777)
}

func (arunner *WorkerRunnerEnvironment) ReadJson(path string, value interface{}) error {
	cont, err := ioutil.ReadFile(path)
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

func (arunner *WorkerRunnerEnvironment) ExecWorker(run *RunRunner, wc WorkerContext, jobreq *protocol.AgentJobRequestMessage, src []byte) error {
	jlogger := wc.Logger()
	jobExecCtx := wc.JobExecCtx()
	if len(arunner.WorkerArgs) <= 0 {
		return fmt.Errorf("missing WorkerArgs to execute an external worker")
	}
	worker := exec.Command(arunner.WorkerArgs[0], arunner.WorkerArgs[1:]...)
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
	jlogger.Logger.Close()
	jlogger.Current().Complete("Succeeded")
	jlogger.MoveNext()
	mid := make([]byte, 4)
	binary.BigEndian.PutUint32(mid, 1) // NewJobRequest
	in.Write(mid)
	binary.BigEndian.PutUint32(mid, uint32(len(src)))
	in.Write(mid)
	in.Write(src)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-jobExecCtx.Done():
			binary.BigEndian.PutUint32(mid, 2) // CancelRequest
			in.Write(mid)
			binary.BigEndian.PutUint32(mid, uint32(len(src)))
			in.Write(mid)
			in.Write(src)
		case <-done:
		}
	}()
	io.Copy(os.Stdout, out)
	io.Copy(os.Stdout, er)
	worker.Wait()
	if exitcode := worker.ProcessState.ExitCode(); exitcode != 0 {
		return fmt.Errorf("failed to execute worker: %v", exitcode)
	}
	return nil
}
