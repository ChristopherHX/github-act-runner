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

func (token *TemplateToken) FromRawObject(value interface{}) {
	converter := &TemplateTokenConverter{
		AllowExpressions:    true,
		IgnoreDefaultValues: true,
	}
	ret, _ := converter.FromRawObject(value)
	if ret != nil {
		*token = *ret
	}
}

func (token *TemplateToken) ToRawObject() interface{} {
	converter := &TemplateTokenConverter{
		AllowExpressions:    true,
		IgnoreDefaultValues: true,
	}
	ret, _ := converter.ToRawObject(token)
	return ret
}

func (token *TemplateToken) ToJSONRawObject() interface{} {
	converter := &TemplateTokenConverter{
		AllowExpressions:    true,
		IgnoreDefaultValues: true,
		StringKeys:          true,
	}
	ret, _ := converter.ToRawObject(token)
	return ret
}

func (token *TemplateToken) ToYamlNode() *yaml.Node {
	converter := &TemplateTokenConverter{
		AllowExpressions:    true,
		IgnoreDefaultValues: true,
		StringKeys:          true,
	}
	ret, _ := converter.ToYamlNode(token)
	return ret
}

type TemplateTokenConverter struct {
	AllowExpressions    bool // If false expressions cause an error or are encoded as a string
	IgnoreDefaultValues bool // Some act structs use have non present fields, which are encoded into a yaml node
	StringKeys          bool
}

func escapeString(in string) string {
	return strings.ReplaceAll(in, "'", "''")
}

func escapeExpression(in string) string {
	if strings.Contains(in, "${{") || strings.Contains(in, "}}") {
		return fmt.Sprintf("${{ '%s' }}", escapeString(in))
	}
	return in
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

func (converter *TemplateTokenConverter) FromRawObject(value interface{}) (*TemplateToken, error) {
	switch val := value.(type) {
	case string:
		if converter.AllowExpressions {
			// Resolve potential nested expressions and convert them to an expressions object
			if expr, ok := rewriteSubExpression(val, false); ok {
				if expr == "insert" {
					return &TemplateToken{Type: 4, Directive: &expr}, nil
				} else {
					return &TemplateToken{Type: 3, Expr: &expr}, nil

				}
			}
		}
		return &TemplateToken{Type: 0, Lit: &val}, nil
	case []interface{}:
		a := val
		seq := make([]*TemplateToken, len(a))
		for i, v := range a {
			var err error
			(seq)[i], err = converter.FromRawObject(v)
			if err != nil {
				return nil, err
			}
		}
		return &TemplateToken{Type: 1, Seq: &seq}, nil
	case map[interface{}]interface{}:
		_map := make([]MapEntry, 0, 2*len(val))
		for k, v := range val {
			key, err := converter.FromRawObject(k)
			if err != nil {
				return nil, err
			}
			value, err := converter.FromRawObject(v)
			if err != nil {
				return nil, err
			}
			_map = append(_map, MapEntry{
				Key:   key,
				Value: value,
			})
		}
		return &TemplateToken{Type: 2, Map: &_map}, nil
	case bool:
		return &TemplateToken{Type: 5, Bool: &val}, nil
	case float64:
		return &TemplateToken{Type: 6, Num: &val}, nil
	default:
		return nil, fmt.Errorf("unexpected TemplateToken type: %v", val)
	}
}

func (converter *TemplateTokenConverter) ToRawObject(token *TemplateToken) (interface{}, error) {
	switch token.Type {
	case 0:
		if converter.AllowExpressions {
			return escapeExpression(*token.Lit), nil
		}
		return *token.Lit, nil
	case 1:
		a := make([]interface{}, 0)
		for _, v := range *token.Seq {
			c, err := converter.ToRawObject(v)
			if err != nil {
				return nil, err
			}
			a = append(a, c)
		}
		return a, nil
	case 2:
		if converter.StringKeys {
			m := make(map[interface{}]interface{})
			for _, v := range *token.Map {
				k, err := converter.ToRawObject(v.Key)
				if err != nil {
					return nil, err
				}
				m[k], err = converter.ToRawObject(v.Value)
				if err != nil {
					return nil, err
				}
			}
			return m, nil
		} else {
			m := make(map[string]interface{})
			for _, v := range *token.Map {
				k, err := converter.ToRawObject(v.Key)
				if err != nil {
					return nil, err
				}
				if s, ok := k.(string); ok {
					m[s], err = converter.ToRawObject(v.Value)
					if err != nil {
						return nil, err
					}
				} else {
					return nil, fmt.Errorf("unexpected key type %v", k)
				}
			}
			return m, nil
		}
	case 3:
		if !converter.AllowExpressions {
			return nil, fmt.Errorf("expressions are not allowed: %s", *token.Expr)
		}
		return "${{" + *token.Expr + "}}", nil
	case 4:
		if !converter.AllowExpressions {
			return nil, fmt.Errorf("directives are not allowed: %s", *token.Directive)
		}
		return "${{" + *token.Directive + "}}", nil
	case 5:
		return *token.Bool, nil
	case 6:
		return *token.Num, nil
	default:
		return nil, fmt.Errorf("unexpected TemplateToken type: %v", token.Type)
	}
}

func (converter *TemplateTokenConverter) ToYamlNode(token *TemplateToken) (ret *yaml.Node, err error) {
	defer func() {
		if ret != nil {
			if token.Column != nil {
				ret.Column = int(*token.Column)
			}
			if token.Line != nil {
				ret.Line = int(*token.Line)
			}
		}
	}()
	switch token.Type {
	case 0:
		val := *token.Lit
		if converter.AllowExpressions {
			val = escapeExpression(val)
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: val}, nil
	case 1:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Seq {
			r, err := converter.ToYamlNode(v)
			if err != nil {
				return nil, err
			}
			a = append(a, r)
		}
		return &yaml.Node{Kind: yaml.SequenceNode, Content: a}, nil
	case 2:
		a := make([]*yaml.Node, 0)
		for _, v := range *token.Map {
			k, err := converter.ToYamlNode(v.Key)
			if err != nil {
				return nil, err
			}
			v, err := converter.ToYamlNode(v.Value)
			if err != nil {
				return nil, err
			}
			a = append(a, k, v)
		}
		return &yaml.Node{Kind: yaml.MappingNode, Content: a}, nil
	case 3:
		if !converter.AllowExpressions {
			return nil, fmt.Errorf("expressions are not allowed: %s", *token.Expr)
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: "${{" + *token.Expr + "}}"}, nil
	case 4:
		if !converter.AllowExpressions {
			return nil, fmt.Errorf("directives are not allowed: %s", *token.Expr)
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: "${{" + *token.Directive + "}}"}, nil
	case 5:
		val, _ := yaml.Marshal(token.Bool)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}, nil
	case 6:
		val, _ := yaml.Marshal(token.Num)
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: string(val[:len(val)-1])}, nil
	case 7:
		return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.FlowStyle, Value: "null"}, nil
	default:
		return nil, fmt.Errorf("unexpected TemplateToken type: %v", token.Type)
	}
}

func (converter *TemplateTokenConverter) FromYamlNode(node *yaml.Node) (ret *TemplateToken, err error) {
	defer func() {
		if ret != nil && (node.Column != 0 || node.Line != 0) {
			column := int32(node.Column)
			line := int32(node.Line)
			ret.Column = &column
			ret.Line = &line
		}
	}()
	retNil := func() (*TemplateToken, error) {
		if converter.IgnoreDefaultValues {
			return nil, nil
		}
		return &TemplateToken{Type: 7}, nil
	}
	if node == nil || node.IsZero() {
		return retNil()
	}
	switch node.Kind {
	case yaml.DocumentNode:
		return converter.FromYamlNode(node.Content[0])
	case yaml.ScalarNode:
		var number float64
		var c interface{}
		var val interface{}
		if node.Tag == "!!null" || converter.IgnoreDefaultValues && node.Value == "" {
			return retNil()
		}
		if err := node.Decode(&number); err == nil {
			if converter.IgnoreDefaultValues && number == 0 {
				return nil, nil
			}
			val = number
		} else if err := node.Decode(&c); err == nil {
			if b, ok := c.(bool); ok {
				if !converter.IgnoreDefaultValues || b {
					val = b
				}
			} else if s, ok := c.(string); ok {
				if !converter.IgnoreDefaultValues || s != "" {
					val = s
				}
			}
		}
		return converter.FromRawObject(val)
	case yaml.SequenceNode:
		content := make([]*TemplateToken, len(node.Content))
		for i := 0; i < len(content); i++ {
			content[i], err = converter.FromYamlNode(node.Content[i])
			if err != nil {
				return nil, err
			}
		}
		return &TemplateToken{
			Type: 1,
			Seq:  &content,
		}, nil
	case yaml.MappingNode:
		cap := len(node.Content) / 2
		content := make([]MapEntry, 0, cap)
		for i := 0; i < cap; i++ {
			key, err := converter.FromYamlNode(node.Content[i*2])
			if err != nil {
				return nil, err
			}
			val, err := converter.FromYamlNode(node.Content[i*2+1])
			if err != nil {
				return nil, err
			}
			// skip null values of some yaml structures of act
			if key != nil && val != nil {
				content = append(content, MapEntry{Key: key, Value: val})
			}
		}
		return &TemplateToken{
			Type: 2,
			Map:  &content,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected yaml kind: %v", node.Kind)
	}
}
