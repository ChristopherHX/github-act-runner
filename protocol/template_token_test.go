package protocol

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestToTemplateToken(t *testing.T) {
	node := &yaml.Node{}
	err := yaml.Unmarshal([]byte(`
on: push
jobs:
  test:
    name: ${{ contains(github.token, '=') }}
    runs-on: ubuntu-latest
    steps:
    - run: echo ${{ '${{ Hello World }}' }}
`), node)
	if err != nil {
		t.Error(err)
	}
	token := ToTemplateToken(*node)
	kv := (*token.Map)[0]
	if *kv.Key.Lit != "on" {
		t.Error("Unexpected key")
	}
	kv = (*token.Map)[1]
	if *kv.Key.Lit != "jobs" {
		t.Error("Unexpected key")
	}
	jobkv := (*(*kv.Value.Map)[0].Value.Map)[0]
	if *jobkv.Key.Lit != "name" {
		t.Error("Unexpected key")
	}
	if *jobkv.Value.Expr != "contains(github.token, '=')" {
		t.Error("Unexpected expression")
	}
	jobkv = (*(*(*(*kv.Value.Map)[0].Value.Map)[2].Value.Seq)[0].Map)[0]
	if *jobkv.Value.Expr != "format('echo {0}', '${{ Hello World }}')" {
		t.Error("Unexpected expression")
	}
}
