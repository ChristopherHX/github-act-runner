package protocol

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type MapEntry struct {
	Key   *TemplateToken
	Value *TemplateToken
}

type TemplateToken struct {
	FileID    *int32
	Line      *int32
	Column    *int32
	Type      int32
	Bool      *bool
	Num       *float64
	Lit       *string
	Expr      *string
	Directive *string
	Seq       *[]*TemplateToken
	Map       *[]MapEntry
}

func (token *TemplateToken) UnmarshalJSON(data []byte) error {
	if json.Unmarshal(data, &token.Bool) == nil {
		token.Type = 5
		return nil
	} else if json.Unmarshal(data, &token.Num) == nil {
		token.Bool = nil
		token.Type = 6
		return nil
	} else if json.Unmarshal(data, &token.Lit) == nil {
		token.Bool = nil
		token.Num = nil
		token.Type = 0
		return nil
	} else {
		token.Bool = nil
		token.Num = nil
		token.Lit = nil
		type TemplateToken2 TemplateToken
		return json.Unmarshal(data, (*TemplateToken2)(token))
	}
}

func escapeFormatString(in string) string {
	return strings.ReplaceAll(strings.ReplaceAll(in, "{", "{{"), "}", "}}")
}

func rewriteSubExpression(in string, forceFormat bool) (string, bool) {
	if !strings.Contains(in, "${{") || !strings.Contains(in, "}}") {
		return in, false
	}

	strPattern := regexp.MustCompile("(?:''|[^'])*'")
	pos := 0
	exprStart := -1
	strStart := -1
	var results []string
	formatOut := ""
	for pos < len(in) {
		if strStart > -1 {
			matches := strPattern.FindStringIndex(in[pos:])
			if matches == nil {
				panic("unclosed string.")
			}

			strStart = -1
			pos += matches[1]
		} else if exprStart > -1 {
			exprEnd := strings.Index(in[pos:], "}}")
			strStart = strings.Index(in[pos:], "'")

			if exprEnd > -1 && strStart > -1 {
				if exprEnd < strStart {
					strStart = -1
				} else {
					exprEnd = -1
				}
			}

			if exprEnd > -1 {
				formatOut += fmt.Sprintf("{%d}", len(results))
				results = append(results, strings.TrimSpace(in[exprStart:pos+exprEnd]))
				pos += exprEnd + 2
				exprStart = -1
			} else if strStart > -1 {
				pos += strStart + 1
			} else {
				panic("unclosed expression.")
			}
		} else {
			exprStart = strings.Index(in[pos:], "${{")
			if exprStart != -1 {
				formatOut += escapeFormatString(in[pos : pos+exprStart])
				exprStart = pos + exprStart + 3
				pos = exprStart
			} else {
				formatOut += escapeFormatString(in[pos:])
				pos = len(in)
			}
		}
	}

	if len(results) == 1 && formatOut == "{0}" && !forceFormat {
		return results[0], true
	}

	out := fmt.Sprintf("format('%s', %s)", strings.ReplaceAll(formatOut, "'", "''"), strings.Join(results, ", "))
	return out, true
}

func (token *TemplateToken) FromRawObject(value interface{}) {
	switch val := value.(type) {
	case string:
		// Resolve potential nested expressions and convert them to an expressions object
		if expr, ok := rewriteSubExpression(val, false); ok {
			if directive := strings.Trim(expr, " "); directive == "insert" {
				token.Type = 4
				token.Directive = &directive
			} else {
				token.Type = 3
				token.Expr = &expr
			}
		} else {
			token.Type = 0
			token.Lit = &val
		}
	case []interface{}:
		token.Type = 1
		a := val
		seq := make([]*TemplateToken, len(a))
		token.Seq = &seq
		for i, v := range a {
			e := TemplateToken{}
			e.FromRawObject(v)
			(*token.Seq)[i] = &e
		}
	case map[interface{}]interface{}:
		token.Type = 2
		_map := make([]MapEntry, 0)
		token.Map = &_map
		for k, v := range val {
			key := &TemplateToken{}
			key.FromRawObject(k)
			value := &TemplateToken{}
			value.FromRawObject(v)
			_map = append(_map, MapEntry{
				Key:   key,
				Value: value,
			})
		}
	case bool:
		token.Type = 5
		token.Bool = &val
	case float64:
		token.Type = 6
		token.Num = &val
	}
}

func (token *TemplateToken) ToRawObject() interface{} {
	switch token.Type {
	case 0:
		return *token.Lit
	case 1:
		a := make([]interface{}, 0)
		for _, v := range *token.Seq {
			a = append(a, v.ToRawObject())
		}
		return a
	case 2:
		m := make(map[interface{}]interface{})
		for _, v := range *token.Map {
			m[v.Key.ToRawObject()] = v.Value.ToRawObject()
		}
		return m
	case 3:
		return "${{" + *token.Expr + "}}"
	case 4:
		return "${{" + *token.Directive + "}}"
	case 5:
		return *token.Bool
	case 6:
		return *token.Num
	}
	return nil
}

func (token *TemplateToken) ToJSONRawObject() interface{} {
	switch token.Type {
	case 0:
		return *token.Lit
	case 1:
		a := make([]interface{}, 0)
		for _, v := range *token.Seq {
			a = append(a, v.ToJSONRawObject())
		}
		return a
	case 2:
		m := make(map[string]interface{})
		for _, v := range *token.Map {
			k := v.Key.ToJSONRawObject()
			if s, ok := k.(string); ok {
				m[s] = v.Value.ToJSONRawObject()
			}
		}
		return m
	case 3:
		return "${{" + *token.Expr + "}}"
	case 4:
		return "${{" + *token.Directive + "}}"
	case 5:
		return *token.Bool
	case 6:
		return *token.Num
	}
	return nil
}

func (token *TemplateToken) ToYamlNode() *yaml.Node {
	switch token.Type {
	case 0:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: *token.Lit}
	case 1:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Seq {
			a = append(a, v.ToYamlNode())
		}
		return &yaml.Node{Kind: yaml.SequenceNode, Content: a}
	case 2:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Map {
			a = append(a, v.Key.ToYamlNode(), v.Value.ToYamlNode())
		}
		return &yaml.Node{Kind: yaml.MappingNode, Content: a}
	case 3:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: "${{" + *token.Expr + "}}"}
	case 4:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: "${{" + *token.Directive + "}}"}
	case 5:
		val, _ := yaml.Marshal(token.Bool)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}
	case 6:
		val, _ := yaml.Marshal(token.Num)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}
	case 7:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: "null"}
	}
	return nil
}

func ToTemplateToken(node yaml.Node) *TemplateToken {
	switch node.Kind {
	case yaml.ScalarNode:
		var number float64
		var str string
		var b bool
		var val interface{}
		if node.Tag == "!!null" || node.Value == "" {
			return nil
		}
		if err := node.Decode(&number); err == nil {
			if number == 0 {
				return nil
			}
			val = number
		} else if err := node.Decode(&b); err == nil {
			// container.reuse causes an error
			if !b {
				return nil
			}
			val = b
		} else if err := node.Decode(&str); err == nil {
			val = str
		}
		token := &TemplateToken{}
		token.FromRawObject(val)
		return token
	case yaml.SequenceNode:
		content := make([]*TemplateToken, len(node.Content))
		for i := 0; i < len(content); i++ {
			content[i] = ToTemplateToken(*node.Content[i])
		}
		return &TemplateToken{
			Type: 1,
			Seq:  &content,
		}
	case yaml.MappingNode:
		cap := len(node.Content) / 2
		content := make([]MapEntry, 0, cap)
		for i := 0; i < cap; i++ {
			key := ToTemplateToken(*node.Content[i*2])
			val := ToTemplateToken(*node.Content[i*2+1])
			// skip null values of some yaml structures of act
			if key != nil && val != nil {
				content = append(content, MapEntry{Key: key, Value: val})
			}
		}
		return &TemplateToken{
			Type: 2,
			Map:  &content,
		}
	}
	return nil
}
