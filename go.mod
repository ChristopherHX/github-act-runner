module github.com/ChristopherHX/github-act-runner

go 1.16

require (
	github.com/AlecAivazis/survey/v2 v2.3.6
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/uuid v1.3.0
	github.com/mtibben/androiddnsfix v0.0.0-20200907095054-ff0280446354
	github.com/nektos/act v0.2.22
	github.com/robertkrimen/otto v0.0.0-20210614181706-373ff5438452
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.7.0
	github.com/spf13/viper v1.8.1 // indirect
	golang.org/x/net v0.7.0
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/nektos/act => ./act
