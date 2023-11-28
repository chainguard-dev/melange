package build

import "runtime"

type Runner string

const (
	runnerBubblewrap Runner = "bubblewrap"
	runnerDocker     Runner = "docker"
	runnerLima       Runner = "lima"
	runnerKubernetes Runner = "kubernetes"
	// more to come
)

// GetDefaultRunner returns the default runner to use.
// Currently, this is bubblewrap, but will be replaced with determining by platform.
func GetDefaultRunner() Runner {
	var r Runner
	switch runtime.GOOS {
	case "linux":
		r = runnerBubblewrap
	case "darwin":
		// darwin is the same as default, but we want to keep it explicit
		r = runnerDocker
	default:
		r = runnerDocker
	}
	return r
}

// GetAllRunners returns a list of all valid runners.
func GetAllRunners() []Runner {
	return []Runner{
		runnerBubblewrap,
		runnerDocker,
		runnerLima,
		runnerKubernetes,
	}
}
