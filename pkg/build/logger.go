package build

type Logger interface {
	Printf(format string, v ...any)
	Debugf(format string, v ...any)
}

type nopLogger struct{}

func (n nopLogger) Debugf(format string, v ...any) {}

func (n nopLogger) Printf(string, ...any) {}
