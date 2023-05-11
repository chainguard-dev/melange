package container

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

const (
	runnerWorkdir = "/home/build"
)

func digestFromRef(ref string) (string, error) {
	dig, err := name.NewDigest(ref)
	if err != nil {
		return "", err
	}
	digest := strings.SplitN(dig.DigestStr(), ":", 2)
	if len(digest) != 2 {
		return "", fmt.Errorf("invalid digest %s", dig.DigestStr())
	}
	imgDigest := digest[1]
	return imgDigest, nil
}
