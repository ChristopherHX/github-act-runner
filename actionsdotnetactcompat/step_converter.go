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

		continueOnError := false
		if step.ContinueOnError != nil {
			tmpcontinueOnError, ok := step.ContinueOnError.ToRawObject().(bool)
			if !ok {
				return nil, fmt.Errorf("ContinueOnError: act doesn't support expressions here")
			}
			continueOnError = tmpcontinueOnError
		}
		var timeoutMinutes int64 = 0
		if step.TimeoutInMinutes != nil {
			rawTimeout, ok := step.TimeoutInMinutes.ToRawObject().(float64)
			if !ok {
				return nil, fmt.Errorf("TimeoutInMinutes: act doesn't support expressions here")
			}
			timeoutMinutes = int64(rawTimeout)
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
					ID:               step.ContextName,
					If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
					Name:             displayName,
					Run:              scriptContent,
					WorkingDirectory: wd,
					Shell:            shell,
					ContinueOnError:  continueOnError,
					TimeoutMinutes:   timeoutMinutes,
					Env:              *env,
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
				ID:               step.ContextName,
				If:               yaml.Node{Kind: yaml.ScalarNode, Value: step.Condition},
				Name:             displayName,
				Uses:             uses,
				WorkingDirectory: "",
				With:             with,
				ContinueOnError:  continueOnError,
				TimeoutMinutes:   timeoutMinutes,
				Env:              *env,
			})
		}
	}
	return steps, nil
}
