package versions

import (
	"errors"
	"regexp"
)

var (
	versionRegex = func() *regexp.Regexp {
		re := regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)
		re.Longest()
		return re
	}()

	versionWithEpochRegex = func() *regexp.Regexp {
		re := regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?(-r[0-9]+)$`)
		re.Longest()
		return re
	}()
)

var (
	ErrInvalidVersion     = errors.New("not a valid Wolfi package version")
	ErrInvalidFullVersion = errors.New("not a valid full Wolfi package version (with epoch)")
)

func ValidateWithoutEpoch(v string) error {
	if !versionRegex.MatchString(v) {
		return ErrInvalidVersion
	}
	return nil
}

func ValidateWithEpoch(v string) error {
	if !versionWithEpochRegex.MatchString(v) {
		return ErrInvalidFullVersion
	}
	return nil
}
