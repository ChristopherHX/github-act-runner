package runnerconfiguration

import (
	"fmt"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

func (config *RemoveRunner) Remove(settings *RunnerSettings, survey Survey, auth *protocol.GitHubAuthResult) (*RunnerSettings, error) {
	c := config.GetHttpClient()
	var instancesToRemove []*RunnerInstance
	for _, i := range settings.Instances {
		if (len(config.URL) == 0 || i.RegistrationURL == config.URL) || (len(config.Name) == 0 || i.Agent.Name == config.Name) {
			instancesToRemove = append(instancesToRemove, i)
		}
	}
	if len(instancesToRemove) == 0 {
		return settings, nil
	}
	if !config.Unattended && len(instancesToRemove) > 1 {
		options := make([]string, len(instancesToRemove))
		for i, instance := range instancesToRemove {
			options[i] = fmt.Sprintf("%v ( %v )", instance.Agent.Name, instance.RegistrationURL)
		}
		result := survey.GetMultiSelectInput("Please select the instances to remove, use --unattended to remove all", options)
		var instancesToRemoveFiltered []*RunnerInstance
		for _, res := range result {
			for i := 0; i < len(options); i++ {
				if options[i] == res {
					instancesToRemoveFiltered = append(instancesToRemoveFiltered, instancesToRemove[i])
				}
			}
		}
		instancesToRemove = instancesToRemoveFiltered
		if len(instancesToRemove) == 0 {
			return nil, fmt.Errorf("nothing selected, no runner matches")
		}
	}
	regurl := ""
	needsPat := false
	for _, i := range instancesToRemove {
		if len(regurl) > 0 && regurl != i.RegistrationURL {
			needsPat = true
		} else {
			regurl = i.RegistrationURL
		}
	}
	if needsPat && len(config.Pat) == 0 {
		if !config.Unattended {
			config.Pat = survey.GetInput("Please enter your Personal Access token", "")
		}
		if len(config.Pat) == 0 {
			return nil, fmt.Errorf("you have to provide a Personal access token with access to the repositories to remove or use the --url parameter")
		}
	}
	for i, instance := range instancesToRemove {
		result := func() error {
			confremove := *config
			confremove.URL = instance.RegistrationURL
			res := auth
			if needsPat {
				// Enshure that gitHubAuth always uses the Personal access token
				confremove.Token = ""
				res = nil
			}
			if res == nil {
				authres, err := confremove.Authenticate(c, survey)
				if err != nil {
					return err
				}
				res = authres
			}

			vssConnection := &protocol.VssConnection{
				Client:    c,
				TenantURL: res.TenantURL,
				Token:     res.Token,
				PoolID:    instance.PoolID,
				Trace:     config.Trace,
			}
			if err := vssConnection.DeleteAgent(instance.Agent); err != nil {
				return fmt.Errorf("failed to remove Runner from server: %v\n", err)
			}
			return nil
		}()
		if result != nil && !config.Force {
			if i == 0 {
				return nil, result
			}
			return settings, result
		}
		for i := range settings.Instances {
			if settings.Instances[i] == instance {
				settings.Instances[i] = settings.Instances[len(settings.Instances)-1]
				settings.Instances = settings.Instances[:len(settings.Instances)-1]
				break
			}
		}
	}
	return settings, nil
}
