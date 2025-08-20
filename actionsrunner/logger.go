package actionsrunner

import (
	"fmt"
)

type BasicLogger interface {
	Printf(format string, a ...interface{})
}

type ConsoleLogger struct{}

func (*ConsoleLogger) Printf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

type PrefixConsoleLogger struct {
	Parent BasicLogger
	Prefix string
}

func (p *PrefixConsoleLogger) Printf(format string, a ...interface{}) {
	p.Parent.Printf("%s "+format, append([]interface{}{p.Prefix}, a...)...)
}
