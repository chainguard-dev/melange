package build

type Logger interface {
	Printf(format string, v ...any)
}

type nopLogger struct{}

func (n nopLogger) Printf(string, ...any) {}
