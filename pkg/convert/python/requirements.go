package python

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ParseRequirementsTxt parses a requirements.txt file and returns a list of
// package names. It ignores comments, extras, and version constraints.
// This is from a modified version of battle-tested code:
// https://github.com/google/osv-scanner/blob/main/pkg/lockfile/parse-requirements-txt.go
func ParseRequirementsTxt(r io.Reader) ([]string, error) {
	packages := []string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		for isLineContinuation(line) {
			line = strings.TrimSuffix(line, "\\")

			if scanner.Scan() {
				line += scanner.Text()
			}
		}

		line = removeComments(line)

		if isNotRequirementLine(line) {
			continue
		}

		detail := parseLine(line)

		packages = append(packages, detail)
	}

	if err := scanner.Err(); err != nil {
		return []string{}, fmt.Errorf("error while scanning: %w", err)
	}

	return packages, nil
}

func isLineContinuation(line string) bool {
	// checks that the line ends with an odd number of back slashes,
	// meaning the last one isn't escaped
	re := regexp.MustCompile(`([^\\]|^)(\\{2})*\\$`)

	return re.MatchString(line)
}

func isNotRequirementLine(line string) bool {
	return line == "" ||
		// flags are not supported
		strings.HasPrefix(line, "-") ||
		// file urls
		strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "http://") ||
		// file paths are not supported (relative or absolute)
		strings.HasPrefix(line, ".") ||
		strings.HasPrefix(line, "/")
}

// https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseLine(line string) string {
	var constraint string
	name := line

	if strings.Contains(line, "==") {
		constraint = "=="
	}

	if strings.Contains(line, ">=") {
		constraint = ">="
	}

	if strings.Contains(line, "~=") {
		constraint = "~="
	}

	if strings.Contains(line, "!=") {
		constraint = "!="
	}

	if constraint != "" {
		unprocessedName, _, _ := strings.Cut(line, constraint)
		name = strings.TrimSpace(unprocessedName)
	}

	return normalizedRequirementName(name)
}

// normalizedName ensures that the package name is normalized per PEP-0503
// and then removing "added support" syntax if present.
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, _and_ Pip itself supports
// non-normalized names in the requirements.txt, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}

func removeComments(line string) string {
	var re = regexp.MustCompile(`(^|\s+)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

func stripDep(dep string) (string, error) {
	// removing all the special chars from the requirements like   "importlib-metadata (>=3.6.0) ; python_version < \"3.10\""
	re := regexp.MustCompile(`[;()\[\]!~=<>]`)
	dep = re.ReplaceAllString(dep, " ")
	depStrip := strings.Split(dep, " ")
	return depStrip[0], nil
}
