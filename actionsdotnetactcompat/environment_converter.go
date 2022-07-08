package actionsdotnetactcompat

import (
	"fmt"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

func ConvertEnvironment(environmentVariables []protocol.TemplateToken) (map[string]string, error) {
	env := make(map[string]string)
	if environmentVariables != nil {
		for _, rawenv := range environmentVariables {
			if tmpenv, ok := rawenv.ToRawObject().(map[interface{}]interface{}); ok {
				for k, v := range tmpenv {
					key, ok := k.(string)
					if !ok {
						return nil, fmt.Errorf("env key: act doesn't support non strings")
					}
					value, ok := v.(string)
					if !ok {
						return nil, fmt.Errorf("env value: act doesn't support non strings")
					}
					env[key] = value
				}
			} else {
				return nil, fmt.Errorf("env: not a map")
			}
		}
	}
	return env, nil
}
