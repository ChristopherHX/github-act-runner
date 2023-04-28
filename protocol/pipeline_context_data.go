package protocol

import (
	"encoding/json"
	"fmt"
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
			var typ int32 = 3
			ctx.Type = &typ
		}
		return nil
	} else if json.Unmarshal(data, &ctx.NumberValue) == nil {
		ctx.BoolValue = nil
		var typ int32 = 4
		ctx.Type = &typ
		return nil
	} else if json.Unmarshal(data, &ctx.StringValue) == nil {
		ctx.BoolValue = nil
		ctx.NumberValue = nil
		var typ int32
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
	case 0:
		return *ctx.StringValue
	case 1:
		a := make([]interface{}, 0)
		if ctx.ArrayValue != nil {
			for _, v := range *ctx.ArrayValue {
				a = append(a, v.ToRawObject())
			}
		}
		return a
	case 2:
		m := make(map[string]interface{})
		if ctx.DictionaryValue != nil {
			for _, v := range *ctx.DictionaryValue {
				m[v.Key] = v.Value.ToRawObject()
			}
		}
		return m
	case 3:
		return *ctx.BoolValue
	case 4:
		return *ctx.NumberValue
	}
	return nil
}

func ToPipelineContextDataWithError(data interface{}) (PipelineContextData, error) {
	if b, ok := data.(bool); ok {
		var typ int32 = 3
		return PipelineContextData{
			Type:      &typ,
			BoolValue: &b,
		}, nil
	} else if n, ok := data.(float64); ok {
		var typ int32 = 4
		return PipelineContextData{
			Type:        &typ,
			NumberValue: &n,
		}, nil
	} else if s, ok := data.(string); ok {
		var typ int32
		return PipelineContextData{
			Type:        &typ,
			StringValue: &s,
		}, nil
	} else if a, ok := data.([]interface{}); ok {
		arr := []PipelineContextData{}
		for _, v := range a {
			e, err := ToPipelineContextDataWithError(v)
			if err != nil {
				return PipelineContextData{}, err
			}
			arr = append(arr, e)
		}
		var typ int32 = 1
		return PipelineContextData{
			Type:       &typ,
			ArrayValue: &arr,
		}, nil
	} else if o, ok := data.(map[string]interface{}); ok {
		obj := []DictionaryContextDataPair{}
		for k, v := range o {
			e, err := ToPipelineContextDataWithError(v)
			if err != nil {
				return PipelineContextData{}, err
			}
			obj = append(obj, DictionaryContextDataPair{Key: k, Value: e})
		}
		var typ int32 = 2
		return PipelineContextData{
			Type:            &typ,
			DictionaryValue: &obj,
		}, nil
	}
	if data == nil {
		return PipelineContextData{}, nil
	}
	return PipelineContextData{}, fmt.Errorf("unknown type")
}

func ToPipelineContextData(data interface{}) PipelineContextData {
	ret, err := ToPipelineContextDataWithError(data)
	if err != nil {
		panic(err)
	}
	return ret
}
