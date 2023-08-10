package build

import "runtime"

type runner string

const (
	runnerBubblewrap runner = "bubblewrap"
	runnerDocker     runner = "docker"
	runnerLima       runner = "lima"
	runnerKubernetes runner = "kubernetes"
	// more to come
)

// GetDefaultRunner returns the default runner to use.
// Currently, this is bubblewrap, but will be replaced with determining by platform.
func GetDefaultRunner() runner {
	var r runner
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
func GetAllRunners() []runner {
	return []runner{
		runnerBubblewrap,
		runnerDocker,
		runnerLima,
		runnerKubernetes,
	}
}
