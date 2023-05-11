package build

type runner string

const (
	runnerBubblewrap runner = "bubblewrap"
	runnerDocker     runner = "docker"
	runnerLima       runner = "lima"
	// more to come
)

// GetDefaultRunner returns the default runner to use.
// Currently, this is bubblewrap, but will be replaced with determining by platform.
func GetDefaultRunner() runner {
	return runnerBubblewrap
}

// GetAllrunners returns a list of all valid runners.
func GetAllRunners() []runner {
	return []runner{
		runnerBubblewrap,
		runnerDocker,
		runnerLima,
	}
}
