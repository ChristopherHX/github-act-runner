package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ChristopherHX/github-act-runner/actionsdotnetactcompat"
	"github.com/ChristopherHX/github-act-runner/actionsrunner"
	"github.com/ChristopherHX/github-act-runner/common"
	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/ChristopherHX/github-act-runner/runnerconfiguration"
	runnerCompat "github.com/ChristopherHX/github-act-runner/runnerconfiguration/compat"
	"github.com/joho/godotenv"
	"github.com/kardianos/service"
	"github.com/nektos/act/pkg/container"

	"github.com/spf13/cobra"
)

type RunRunner struct {
	Once       bool
	Terminal   bool
	Trace      bool
	WorkerArgs []string
	JITConfig  string
}

type JobRun struct {
	RequestID       int64
	JobID           string
	Plan            *protocol.TaskOrchestrationPlanReference
	Name            string
	RegistrationURL string
}

func readLegacyInstance(settings *runnerconfiguration.RunnerSettings, instance *runnerconfiguration.RunnerInstance) int {
	taskAgent := &protocol.TaskAgent{}
	var key *rsa.PrivateKey
	req := &protocol.GitHubAuthResult{}
	err := common.ReadJson("agent.json", taskAgent)
	if err != nil {
		return 1
	}
	{
		cont, err := ioutil.ReadFile("cred.pkcs1")
		if err != nil {
			return 1
		}
		key, err = x509.ParsePKCS1PrivateKey(cont)
		if err != nil {
			return 1
		}
	}
	err = common.ReadJson("auth.json", req)
	if err != nil {
		return 1
	}
	instance.Agent = taskAgent
	instance.PKey = key
	instance.PoolID = settings.PoolID
	instance.RegistrationURL = settings.RegistrationURL
	instance.Auth = req
	return 0
}

func loadConfiguration() (*runnerconfiguration.RunnerSettings, error) {
	settings := &runnerconfiguration.RunnerSettings{}
	{
		err := common.ReadJson("settings.json", settings)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Backward compat <= 0.0.3
				// fmt.Printf("The runner needs to be configured first: %v\n", err.Error())
				// return 1
				settings.PoolID = 1
			} else {
				if err != nil {
					return nil, err
				}
			}
		}
	}
	{
		instance := &runnerconfiguration.RunnerInstance{}
		if readLegacyInstance(settings, instance) == 0 {
			settings.Instances = append(settings.Instances, instance)
		}
		if instance, err := runnerCompat.ToRunnerInstance(runnerCompat.DefaultConfigFileAccess{}); err == nil {
			settings.Instances = append(settings.Instances, instance)
		}
	}
	return settings, nil
}

func (run *RunRunner) Run() int {
	container.SetContainerAllocateTerminal(run.Terminal)
	// trap Ctrl+C
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(channel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listenerctx, cancelListener := context.WithCancel(context.Background())
	defer cancelListener()
	go func() {
		sig := <-channel
		if sig == syscall.SIGTERM {
			fmt.Println("SIGTERM received, cancel any current job and wait for completion")
			cancel()
		} else {
			fmt.Println("CTRL+C received, stop accepting new jobs and exit after all active job are finished")
			cancelListener()
			select {
			case <-ctx.Done():
				return
			case <-channel:
				fmt.Println("CTRL+C received again, cancel any current job and wait for completion")
				cancel()
			}
		}
	}()
	return run.RunWithContext(listenerctx, ctx)
}

func (run *RunRunner) RunWithContext(listenerctx context.Context, ctx context.Context) int {
	var settings *runnerconfiguration.RunnerSettings
	var err error
	if run.JITConfig != "" {
		if settings, err = runnerCompat.ParseJitRunnerConfig(run.JITConfig); err != nil {
			fmt.Printf("jitconfig is corrupted: %v, please reconfigure the runner\n", err.Error())
			return 1
		}
	} else if settings, err = loadConfiguration(); err != nil {
		fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
		return 1
	}
	runner := &actionsrunner.RunRunner{
		Once:     run.Once,
		Trace:    run.Trace,
		Version:  version,
		Settings: settings,
	}
	err = runner.Run(&actionsdotnetactcompat.ActRunner{
		WorkerRunnerEnvironment: actionsrunner.WorkerRunnerEnvironment{
			WorkerArgs: run.WorkerArgs,
		},
	}, listenerctx, ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err.Error())
		return 1
	}
	return 0
}

var version string = "0.8.x-dev"

type interactive struct {
}

func (i *interactive) GetInput(prompt string, def string) string {
	return GetInput(prompt, def)
}
func (i *interactive) GetSelectInput(prompt string, options []string, def string) string {
	return RunnerGroupSurvey(def, options)
}
func (i *interactive) GetMultiSelectInput(prompt string, options []string) []string {
	return GetMultiSelectInput(prompt, options)
}

type RunRunnerSvc struct {
	stop func()
	wait chan error
}

func (svc *RunRunnerSvc) Start(s service.Service) error {
	runner := &RunRunner{}

	ctx, cancel := context.WithCancel(context.Background())
	listenerctx, cancelListener := context.WithCancel(context.Background())
	svc.stop = func() {
		cancelListener()
	}
	svc.wait = make(chan error)
	go func() {
		defer cancelListener()
		defer cancel()
		defer close(svc.wait)
		code := runner.RunWithContext(listenerctx, ctx)
		if code != 0 {
			svc.wait <- fmt.Errorf("runner failed with exit code %v", code)
		} else {
			svc.wait <- nil
		}
		s.Stop()
	}()
	return nil
}

func (svc *RunRunnerSvc) Stop(s service.Service) error {
	svc.stop()
	if err, ok := <-svc.wait; ok && err != nil {
		return err
	}
	return nil
}

func main() {
	config := &runnerconfiguration.ConfigureRunner{}
	run := &RunRunner{}
	remove := &runnerconfiguration.RemoveRunner{}
	printJITConfig := false
	saveActionsRunnerConfig := false
	var cmdConfigure = &cobra.Command{
		Use:   "configure",
		Short: "Configure your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			config.ReadFromEnvironment()
			settings := &runnerconfiguration.RunnerSettings{}
			if !printJITConfig {
				settings, _ = loadConfiguration()
			}
			settings, err := config.Configure(settings, &interactive{}, nil)
			if printJITConfig {
				var jitconfig string
				if err == nil {
					jitconfig, err = runnerCompat.ToJitRunnerConfig(settings.Instances[0])
				}
				if err != nil {
					fmt.Printf("failed to configure: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Println(jitconfig)
				}
			} else {
				if settings != nil {
					os.Remove("agent.json")
					os.Remove("auth.json")
					os.Remove("cred.pkcs1")
					if saveActionsRunnerConfig && len(settings.Instances) == 1 {
						runnerCompat.FromRunnerInstance(settings.Instances[0], runnerCompat.DefaultConfigFileAccess{})
					} else {
						common.WriteJson("settings.json", settings)
					}
				}
				if err != nil {
					fmt.Printf("failed to configure: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Printf("success\n")
					os.Exit(0)
				}
			}
		},
	}

	cmdConfigure.Flags().StringVar(&config.URL, "url", "", "url of your repository, organization or enterprise")
	cmdConfigure.Flags().StringVar(&config.Token, "token", "", "runner registration token")
	cmdConfigure.Flags().StringVar(&config.Pat, "pat", "", "personal access token with access to your repository, organization or enterprise")
	cmdConfigure.Flags().StringSliceVarP(&config.Labels, "labels", "l", []string{}, "custom user labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Name, "name", "", "custom runner name")
	cmdConfigure.Flags().BoolVar(&config.NoDefaultLabels, "no-default-labels", false, "do not automatically add the following system labels: self-hosted, "+runtime.GOOS+" and "+runtime.GOARCH)
	cmdConfigure.Flags().StringSliceVar(&config.SystemLabels, "system-labels", []string{}, "custom system labels for your new runner")
	cmdConfigure.Flags().StringVar(&config.Token, "runnergroup", "", "name of the runner group to use will ask if more than one is available")
	cmdConfigure.Flags().BoolVar(&config.Unattended, "unattended", false, "suppress shell prompts during configure")
	cmdConfigure.Flags().BoolVar(&config.Trace, "trace", false, "trace http communication with the github action service")
	cmdConfigure.Flags().BoolVar(&config.Ephemeral, "ephemeral", false, "configure a single use runner, runner deletes it's setting.json ( and the actions service should remove their registrations at the same time ) after executing one job ( implies '--once' on run ). This is not supported for multi runners.")
	cmdConfigure.Flags().StringVar(&config.RunnerGuard, "runner-guard", "", "reject jobs and configure act (deprecated, code removed)")
	cmdConfigure.Flags().BoolVar(&config.Replace, "replace", false, "replace any existing runner with the same name")
	cmdConfigure.Flags().BoolVar(&config.DisableUpdate, "disableupdate", false, "actions/runner disable updates (has no effect)")
	cmdConfigure.Flags().BoolVar(&printJITConfig, "print-jitconfig", false, "print the runner configuration as jitconfig")
	cmdConfigure.Flags().BoolVar(&saveActionsRunnerConfig, "save-actionsrunnerconfig", false, "use the format of actions/runner to save the configuration")
	cmdConfigure.Flags().StringVar(&config.WorkFolder, "work", "_work", "actions/runner work folder (has no effect)")

	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "Run your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(run.Run())
		},
	}

	cmdRun.Flags().BoolVar(&run.Once, "once", false, "only execute one job and exit")
	cmdRun.Flags().BoolVarP(&run.Terminal, "terminal", "t", true, "allocate a pty if possible")
	cmdRun.Flags().BoolVar(&run.Trace, "trace", false, "trace http communication with the github action service")
	cmdRun.Flags().StringSliceVar(&run.WorkerArgs, "worker-args", []string{}, "custom worker for your runner")
	cmdRun.Flags().StringVarP(&run.JITConfig, "jitconfig", "", os.Getenv("ACTIONS_RUNNER_INPUT_JITCONFIG"), "read the runner configuration from the jitconfig")
	var jitConfig string
	local, _ := common.LookupEnvBool("ACTIONS_RUNNER_INPUT_LOCAL")
	var cmdRemove = &cobra.Command{
		Use:   "remove",
		Short: "Remove your self-hosted runner",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			remove.ReadFromEnvironment()
			var settings *runnerconfiguration.RunnerSettings
			var err error
			if !local {
				if jitConfig != "" {
					if settings, err = runnerCompat.ParseJitRunnerConfig(jitConfig); err != nil {
						fmt.Printf("jitconfig is corrupted: %v, please reconfigure the runner\n", err.Error())
						os.Exit(1)
					}
				} else if settings, err = loadConfiguration(); err != nil {
					fmt.Printf("settings.json is corrupted: %v, please reconfigure the runner\n", err.Error())
					os.Exit(1)
				}
				settings, err = remove.Remove(settings, &interactive{}, nil)
			}
			if (settings != nil || local) && jitConfig == "" {
				os.Remove("agent.json")
				os.Remove("auth.json")
				os.Remove("cred.pkcs1")
				os.Remove(".runner")
				os.Remove(".credentials")
				os.Remove(".credentials_rsaparams")

				if !local && len(settings.Instances) > 0 {
					common.WriteJson("settings.json", settings)
				} else {
					os.Remove("settings.json")
				}
			}
			if err != nil {
				fmt.Printf("failed to remove: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("success\n")
				os.Exit(0)
			}
		},
	}

	cmdRemove.Flags().StringVar(&remove.URL, "url", "", "url of your repository, organization or enterprise ( required to unconfigure version <= 0.0.3 )")
	cmdRemove.Flags().StringVar(&remove.Token, "token", "", "runner registration or remove token")
	cmdRemove.Flags().StringVar(&remove.Pat, "pat", "", "personal access token with access to your repository, organization or enterprise")
	cmdRemove.Flags().BoolVar(&remove.Unattended, "unattended", false, "suppress shell prompts during configure")
	cmdRemove.Flags().StringVar(&remove.Name, "name", "", "name of the runner to remove")
	cmdRemove.Flags().BoolVar(&remove.Trace, "trace", false, "trace http communication with the github action service")
	cmdRemove.Flags().BoolVar(&remove.Force, "force", false, "force remove the instance even if the service responds with an error")
	cmdRemove.Flags().StringVarP(&jitConfig, "jitconfig", "", os.Getenv("ACTIONS_RUNNER_INPUT_JITCONFIG"), "read the runner configuration from the jitconfig, this doesn't replace token/pat")
	cmdRemove.Flags().BoolVar(&local, "local", local, "only delete the configuration")

	var cmdWorker = &cobra.Command{
		Use:   "worker",
		Short: "Run as self-hosted runner worker, can be used to create ephemeral worker without exposing other job requests",
		Args:  cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			ccontext, cancelccontext := context.WithCancel(context.Background())
			go func() {
				execcontext, cancelExec := context.WithCancel(context.Background())
				defer cancelExec()
				buf := make([]byte, 4)
				for {
					os.Stdin.Read(buf)
					messageType := binary.BigEndian.Uint32(buf)
					os.Stdin.Read(buf)
					messageLength := binary.BigEndian.Uint32(buf)
					src := make([]byte, messageLength)
					os.Stdin.Read(src)
					switch messageType {
					case 1:
						jobreq := &protocol.AgentJobRequestMessage{}
						json.Unmarshal(src, jobreq)
						go func() {
							defer cancelExec()
							defer cancelccontext()
							wc := &actionsrunner.DefaultWorkerContext{
								RunnerMessage:       jobreq,
								JobExecutionContext: execcontext,
								RunnerLogger:        &actionsrunner.ConsoleLogger{},
							}
							wc.Init()
							wc.Logger().Append(protocol.CreateTimelineEntry(jobreq.JobID, "__setup", "Set up Job")).Start()
							wc.Logger().MoveNext()
							actionsdotnetactcompat.ExecWorker(jobreq, wc)
						}()
					default:
						cancelExec()
					}
				}
			}()
			<-ccontext.Done()
		},
	}
	var cmdSvc = &cobra.Command{
		Use:   "svc",
		Short: "Manage the runner as a system service",
	}

	envFile := ".env"
	cmdSvc.PersistentFlags().StringVar(&envFile, "env-file", envFile, "godotenv file with environment variables for the service")

	wd, _ := os.Getwd()
	svcRun := &cobra.Command{
		Use:   "run",
		Short: "Used as service entrypoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := os.Chdir(wd)
			if err != nil {
				return err
			}
			stdOut, err := os.OpenFile("github-act-runner-log.txt", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)
			if err == nil {
				os.Stdout = stdOut
				defer os.Stdout.Close()
			}
			stdErr, err := os.OpenFile("github-act-runner-log-error.txt", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)
			if err == nil {
				os.Stderr = stdErr
				defer os.Stderr.Close()
			}

			err = godotenv.Overload(envFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load godotenv file '%s': %s\n", envFile, err.Error())
			}

			svc, err := service.New(&RunRunnerSvc{}, getSvcConfig(wd, envFile))

			if err != nil {
				return err
			}
			return svc.Run()
		},
	}
	svcRun.Flags().StringVar(&wd, "working-directory", wd, "path to the working directory of the runner config")
	svcInstall := &cobra.Command{
		Use:   "install",
		Short: "Install the service may require admin privileges",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New(&RunRunnerSvc{}, getSvcConfig(wd, envFile))

			if err != nil {
				return err
			}
			err = svc.Install()
			if err != nil {
				return err
			}
			fmt.Printf("Success\nConsider adding required env variables for your jobs like HOME or PATH to your '%s' godotenv file\nSee https://pkg.go.dev/github.com/joho/godotenv for the syntax\n", envFile)
			return nil
		},
	}
	svcUninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the service may require admin privileges",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New(&RunRunnerSvc{}, getSvcConfig(wd, envFile))

			if err != nil {
				return err
			}
			return svc.Uninstall()
		},
	}
	svcStart := &cobra.Command{
		Use:   "start",
		Short: "Start the service may require admin privileges",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New(&RunRunnerSvc{}, getSvcConfig(wd, envFile))

			if err != nil {
				return err
			}
			return svc.Start()
		},
	}
	svcStop := &cobra.Command{
		Use:   "stop",
		Short: "Stop the service may require admin privileges",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New(&RunRunnerSvc{}, getSvcConfig(wd, envFile))

			if err != nil {
				return err
			}
			return svc.Stop()
		},
	}
	cmdSvc.AddCommand(svcInstall, svcStart, svcStop, svcRun, svcUninstall)

	var rootCmd = &cobra.Command{
		Use:     "github-act-runner",
		Version: version,
	}
	rootCmd.AddCommand(cmdConfigure, cmdRun, cmdRemove, cmdWorker, cmdSvc)
	rootCmd.Execute()
}

func getSvcConfig(wd string, envFile string) *service.Config {
	svcConfig := &service.Config{
		Name:        "github-act-runner",
		DisplayName: "GitHub Act Runner",
		Description: "Cross platform GitHub Actions Runner.",
		Arguments:   []string{"svc", "run", "--working-directory", wd, "--env-file", envFile},
	}
	if runtime.GOOS == "darwin" {
		svcConfig.Option = service.KeyValue{
			"KeepAlive":   true,
			"RunAtLoad":   true,
			"UserService": os.Getuid() != 0,
		}
	}
	return svcConfig
}
