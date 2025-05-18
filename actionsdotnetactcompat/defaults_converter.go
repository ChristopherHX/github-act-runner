package actionsdotnetactcompat

import (
	"encoding/json"
	"fmt"

	"github.com/ChristopherHX/github-act-runner/protocol"
	"github.com/actions-oss/act-cli/pkg/model"
)

func ConvertDefaults(jobDefaults []protocol.TemplateToken) (model.Defaults, error) {
	defaults := model.Defaults{}
	if jobDefaults != nil {
		for _, rawenv := range jobDefaults {
			rawobj := rawenv.ToRawObject()
			rawobj = toStringMap(rawobj)
			b, err := json.Marshal(rawobj)
			if err != nil {
				return model.Defaults{}, fmt.Errorf("Failed to eval defaults")
			}
			json.Unmarshal(b, &defaults)
		}
	}
	return defaults, nil
}
