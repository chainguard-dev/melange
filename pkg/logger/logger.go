package logger

import (
	"chainguard.dev/apko/pkg/log"
)

type NopLogger struct{}

func (n NopLogger) Debugf(fmt string, args ...interface{})  {}
func (n NopLogger) Fatalf(fmt string, args ...interface{})  {}
func (n NopLogger) Errorf(fmt string, args ...interface{})  {}
func (n NopLogger) Printf(fmt string, args ...interface{})  {}
func (n NopLogger) Infof(fmt string, args ...interface{})   {}
func (n NopLogger) Warnf(fmt string, args ...interface{})   {}
func (n NopLogger) SetLevel(level log.Level)                {}
func (n NopLogger) WithFields(fields log.Fields) log.Logger { return n }
