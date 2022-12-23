package build

type Logger interface {
	Printf(format string, v ...any)
	SetPrefix(prefix string)
}

type nopLogger struct{}

func (n nopLogger) Printf(_ string, _ ...any) {}

func (n nopLogger) SetPrefix(_ string) {}
