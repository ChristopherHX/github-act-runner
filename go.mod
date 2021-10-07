module github.com/ChristopherHX/github-act-runner

go 1.16

require (
	github.com/AlecAivazis/survey/v2 v2.3.2
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.2.0
	github.com/mtibben/androiddnsfix v0.0.0-20200907095054-ff0280446354
	github.com/nektos/act v0.2.22
	github.com/robertkrimen/otto v0.0.0-20210614181706-373ff5438452
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/nektos/act => ./act
