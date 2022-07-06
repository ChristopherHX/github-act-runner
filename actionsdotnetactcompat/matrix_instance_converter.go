package actionsdotnetactcompat

import (
	"fmt"

	"github.com/ChristopherHX/github-act-runner/protocol"
)

func ConvertMatrixInstance(contextData map[string]protocol.PipelineContextData) (map[string]interface{}, error) {
	matrix := make(map[string]interface{})
	if rawMatrix, ok := contextData["matrix"]; ok {
		rawobj := rawMatrix.ToRawObject()
		if tmpmatrix, ok := rawobj.(map[string]interface{}); ok {
			matrix = tmpmatrix
		} else if rawobj != nil {
			return nil, fmt.Errorf("matrix: not a map")
		}
	}
	return matrix, nil
}
