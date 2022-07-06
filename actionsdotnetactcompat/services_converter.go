package actionsdotnetactcompat

import (
	"encoding/json"
	"fmt"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/nektos/act/pkg/model"
)

func ConvertServiceContainer(jobServiceContainers *protocol.TemplateToken) (map[string]*model.ContainerSpec, error) {
	services := make(map[string]*model.ContainerSpec)
	if jobServiceContainers != nil {
		rawServiceContainer, ok := jobServiceContainers.ToRawObject().(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("Job service container is not nil, but also not a map")
		}
		for name, rawcontainer := range rawServiceContainer {
			containerName, ok := name.(string)
			if !ok {
				return nil, fmt.Errorf("containername is not a string")
			}
			spec := &model.ContainerSpec{}
			b, err := json.Marshal(toStringMap(rawcontainer))
			if err != nil {
				return nil, fmt.Errorf("Failed to serialize ContainerSpec")
			}
			err = json.Unmarshal(b, &spec)
			if err != nil {
				return nil, fmt.Errorf("Failed to deserialize ContainerSpec")
			}
			services[containerName] = spec
		}
	}
	return services, nil
}
