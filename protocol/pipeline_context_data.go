package protocol

import (
	"encoding/json"
	"fmt"
)

const (
	// PipelineContextData types
	PipelineContextString     = 0
	PipelineContextArray      = 1
	PipelineContextDictionary = 2
	PipelineContextBool       = 3
	PipelineContextNumber     = 4
)

type DictionaryContextDataPair struct {
	Key   string              `json:"k"`
	Value PipelineContextData `json:"v"`
}

type PipelineContextData struct {
	Type            *int32                       `json:"t,omitempty"`
	BoolValue       *bool                        `json:"b,omitempty"`
	NumberValue     *float64                     `json:"n,omitempty"`
	StringValue     *string                      `json:"s,omitempty"`
	ArrayValue      *[]PipelineContextData       `json:"a,omitempty"`
	DictionaryValue *[]DictionaryContextDataPair `json:"d,omitempty"`
}

func (ctx *PipelineContextData) UnmarshalJSON(data []byte) error {
	if json.Unmarshal(data, &ctx.BoolValue) == nil {
		if ctx.BoolValue == nil {
			ctx = nil
		} else {
			var typ int32 = PipelineContextBool
			ctx.Type = &typ
		}
		return nil
	} else if json.Unmarshal(data, &ctx.NumberValue) == nil {
		ctx.BoolValue = nil
		var typ int32 = PipelineContextNumber
		ctx.Type = &typ
		return nil
	} else if json.Unmarshal(data, &ctx.StringValue) == nil {
		ctx.BoolValue = nil
		ctx.NumberValue = nil
		var typ int32 = PipelineContextString
		ctx.Type = &typ
		return nil
	} else {
		ctx.BoolValue = nil
		ctx.NumberValue = nil
		ctx.StringValue = nil
		type PipelineContextData2 PipelineContextData
		return json.Unmarshal(data, (*PipelineContextData2)(ctx))
	}
}

func (ctx PipelineContextData) ToRawObject() interface{} {
	if ctx.Type == nil {
		return nil
	}
	switch *ctx.Type {
	case PipelineContextString:
		return *ctx.StringValue
	case PipelineContextArray:
		a := make([]interface{}, 0)
		if ctx.ArrayValue != nil {
			for _, v := range *ctx.ArrayValue {
				a = append(a, v.ToRawObject())
			}
		}
		return a
	case PipelineContextDictionary:
		m := make(map[string]interface{})
		if ctx.DictionaryValue != nil {
			for _, v := range *ctx.DictionaryValue {
				m[v.Key] = v.Value.ToRawObject()
			}
		}
		return m
	case PipelineContextBool:
		return *ctx.BoolValue
	case PipelineContextNumber:
		return *ctx.NumberValue
	}
	return nil
}

func ToPipelineContextDataWithError(data interface{}) (PipelineContextData, error) {
	switch v := data.(type) {
	case bool:
		var typ int32 = PipelineContextBool
		return PipelineContextData{
			Type:      &typ,
			BoolValue: &v,
		}, nil
	case float64:
		var typ int32 = PipelineContextNumber
		return PipelineContextData{
			Type:        &typ,
			NumberValue: &v,
		}, nil
	case string:
		var typ int32 = PipelineContextString
		return PipelineContextData{
			Type:        &typ,
			StringValue: &v,
		}, nil
	case []interface{}:
		arr := []PipelineContextData{}
		for _, elem := range v {
			e, err := ToPipelineContextDataWithError(elem)
			if err != nil {
				return PipelineContextData{}, err
			}
			arr = append(arr, e)
		}
		var typ int32 = PipelineContextArray
		return PipelineContextData{
			Type:       &typ,
			ArrayValue: &arr,
		}, nil
	case map[string]interface{}:
		obj := []DictionaryContextDataPair{}
		for k, val := range v {
			e, err := ToPipelineContextDataWithError(val)
			if err != nil {
				return PipelineContextData{}, err
			}
			obj = append(obj, DictionaryContextDataPair{Key: k, Value: e})
		}
		var typ int32 = PipelineContextDictionary
		return PipelineContextData{
			Type:            &typ,
			DictionaryValue: &obj,
		}, nil
	case nil:
		return PipelineContextData{}, nil
	default:
		return PipelineContextData{}, fmt.Errorf("unknown type")
	}
}

func ToPipelineContextData(data interface{}) PipelineContextData {
	ret, err := ToPipelineContextDataWithError(data)
	if err != nil {
		panic(err)
	}
	return ret
}
