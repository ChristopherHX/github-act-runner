package actionsdotnetactcompat

func toStringMap(src interface{}) interface{} {
	bi, ok := src.(map[interface{}]interface{})
	if ok {
		res := make(map[string]interface{})
		for k, v := range bi {
			res[k.(string)] = toStringMap(v)
		}
		return res
	}
	return src
}
