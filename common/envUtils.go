package common

import (
	"os"
	"strings"
)

func LookupEnvBool(name string) (bool, bool) {
	if v, ok := os.LookupEnv(name); ok {
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "Y") || strings.EqualFold(v, "Yes") {
			return true, true
		}
		if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "N") || strings.EqualFold(v, "No") {
			return false, true
		}
	}
	return false, false
}
