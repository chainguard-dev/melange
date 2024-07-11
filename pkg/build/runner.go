package build

type Runner string

const (
	runnerBubblewrap Runner = "bubblewrap"
	runnerDocker     Runner = "docker"
	runnerKubernetes Runner = "kubernetes"
	// more to come
)

// GetAllRunners returns a list of all valid runners.
func GetAllRunners() []Runner {
	return []Runner{
		runnerBubblewrap,
		runnerDocker,
		runnerKubernetes,
	}
}
