package actionsdotnetactcompat

import (
	"fmt"
	"strings"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/google/uuid"
	"github.com/nektos/act/pkg/model"
	"gopkg.in/yaml.v3"
)

func ConvertSteps(jobSteps []protocol.ActionStep) ([]*model.Step, error) {
	steps := []*model.Step{}
	for _, step := range jobSteps {
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
		}

		continueOnError := "false"
		if step.ContinueOnError != nil {
			tmpcontinueOnError := step.ContinueOnError.ToRawObject()
			if b, ok := tmpcontinueOnError.(bool); ok {
				continueOnError = fmt.Sprint(b)
			} else if s, ok := tmpcontinueOnError.(string); ok {
				continueOnError = s
			} else {
				return nil, fmt.Errorf("ContinueOnError: Failed to translate")
			}
		}
		var timeoutMinutes string
		if step.TimeoutInMinutes != nil {
			rawTimeout := step.TimeoutInMinutes.ToRawObject()
			if b, ok := rawTimeout.(float64); ok {
				timeoutMinutes = fmt.Sprint(b)
			} else if s, ok := rawTimeout.(string); ok {
				timeoutMinutes = s
			} else {
				return nil, fmt.Errorf("TimeoutInMinutes: Failed to translate")
			}
		}
		var displayName string = ""
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
		case "containerregistry", "repository":
			uses := ""
			if st == "containerregistry" {
				uses = "docker://" + step.Reference.Image
			} else if strings.ToLower(step.Reference.RepositoryType) == "self" {
				uses = step.Reference.Path
			} else {
				uses = step.Reference.Name
				if len(step.Reference.Path) > 0 {
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
