package actionsdotnetactcompat

import (
	"encoding/json"
	"fmt"

	"github.com/actions-oss/act-cli/pkg/model"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

func ConvertDefaults(jobDefaults []protocol.TemplateToken) (model.Defaults, error) {
	defaults := model.Defaults{}
	for _, rawenv := range jobDefaults {
		rawobj := rawenv.ToRawObject()
		rawobj = toStringMap(rawobj)
		b, err := json.Marshal(rawobj)
		if err != nil {
			return model.Defaults{}, fmt.Errorf("failed to eval defaults")
		}
		err = json.Unmarshal(b, &defaults)
		if err != nil {
			fmt.Printf("failed to unmarshal job default: %v", err)
		}
	}
	return defaults, nil
}
