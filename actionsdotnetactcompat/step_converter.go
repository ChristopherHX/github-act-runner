package actionsdotnetactcompat

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nektos/act/pkg/model"
	"gopkg.in/yaml.v3"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

const (
	// Step reference types
	containerRegistryType = "containerregistry"
)

func ConvertSteps(jobSteps []protocol.ActionStep) ([]*model.Step, error) {
	steps := []*model.Step{}
	for i := range jobSteps {
		step := &jobSteps[i]
		st := strings.ToLower(step.Reference.Type)
		inputs := make(map[interface{}]interface{})
		if step.Inputs != nil {
			if tmpinputs, ok := step.Inputs.ToRawObject().(map[interface{}]interface{}); ok {
				inputs = tmpinputs
			} else {
				return nil, fmt.Errorf("step.Inputs: not a map")
			}
		}

		env := &yaml.Node{}
		if step.Environment != nil {
			env = step.Environment.ToYamlNode()
			if env.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("step.env: not a map")
			}
		}

		continueOnError := "false"
		if step.ContinueOnError != nil {
			tmpcontinueOnError := step.ContinueOnError.ToRawObject()
			switch v := tmpcontinueOnError.(type) {
			case bool:
				continueOnError = fmt.Sprint(v)
			case string:
				continueOnError = v
			default:
				return nil, fmt.Errorf("ContinueOnError: Failed to translate")
			}
		}
		var timeoutMinutes string
		if step.TimeoutInMinutes != nil {
			rawTimeout := step.TimeoutInMinutes.ToRawObject()
			switch v := rawTimeout.(type) {
			case float64:
				timeoutMinutes = fmt.Sprint(v)
			case string:
				timeoutMinutes = v
			default:
				return nil, fmt.Errorf("TimeoutInMinutes: Failed to translate")
			}
		}
		var displayName string
		if step.DisplayNameToken != nil {
			rawDisplayName, ok := step.DisplayNameToken.ToRawObject().(string)
			if !ok {
				return nil, fmt.Errorf("DisplayNameToken: act doesn't support no strings")
			}
			displayName = rawDisplayName
		}
		if step.ContextName == "" {
			step.ContextName = "___" + uuid.New().String()
		}

		switch st {
		case "script":
			rawwd, haswd := inputs["workingDirectory"]
			var wd string
			if haswd {
				tmpwd, ok := rawwd.(string)
				if !ok {
					return nil, fmt.Errorf("workingDirectory: act doesn't support non strings")
				}
				wd = tmpwd
			} else {
				wd = ""
			}
			rawshell, hasshell := inputs["shell"]
			shell := ""
			if hasshell {
				sshell, ok := rawshell.(string)
				if ok {
					shell = sshell
				} else {
					return nil, fmt.Errorf("shell is not a string")
				}
			}
			scriptContent, ok := inputs["script"].(string)
			if ok {
				steps = append(steps, &model.Step{
					ID:                 step.ContextName,
					If:                 yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
					Name:               displayName,
					Run:                scriptContent,
					WorkingDirectory:   wd,
					Shell:              shell,
					RawContinueOnError: continueOnError,
					TimeoutMinutes:     timeoutMinutes,
					Env:                *env,
				})
			} else {
				return nil, fmt.Errorf("missing script")
			}
		case containerRegistryType, "repository":
			uses := ""
			if st == containerRegistryType {
				uses = "docker://" + step.Reference.Image
			} else if strings.EqualFold(step.Reference.RepositoryType, "self") {
				uses = step.Reference.Path
			} else {
				uses = step.Reference.Name
				if step.Reference.Path != "" {
					uses = uses + "/" + step.Reference.Path
				}
				uses = uses + "@" + step.Reference.Ref
			}
			with := map[string]string{}
			for k, v := range inputs {
				k, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("with input key is not a string")
				}
				val, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("with input value is not a string")
				}
				with[k] = val
			}

			steps = append(steps, &model.Step{
				ID:                 step.ContextName,
				If:                 yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
				Name:               displayName,
				Uses:               uses,
				WorkingDirectory:   "",
				With:               with,
				RawContinueOnError: continueOnError,
				TimeoutMinutes:     timeoutMinutes,
				Env:                *env,
			})
		}
	}
	return steps, nil
}
