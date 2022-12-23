package build

type Logger interface {
	Printf(format string, v ...any)
	SetPrefix(prefix string)
}

type nopLogger struct{}

func (n nopLogger) Printf(string, ...any) {}

func (n nopLogger) SetPrefix(string) {}
