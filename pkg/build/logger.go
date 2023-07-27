package build

import (
	"chainguard.dev/apko/pkg/log"
)

type nopLogger struct{}

func (n nopLogger) Debugf(fmt string, args ...interface{})  {}
func (n nopLogger) Fatalf(fmt string, args ...interface{})  {}
func (n nopLogger) Errorf(fmt string, args ...interface{})  {}
func (n nopLogger) Printf(fmt string, args ...interface{})  {}
func (n nopLogger) Infof(fmt string, args ...interface{})   {}
func (n nopLogger) Warnf(fmt string, args ...interface{})   {}
func (n nopLogger) SetLevel(level log.Level)                {}
func (n nopLogger) WithFields(fields log.Fields) log.Logger { return n }
