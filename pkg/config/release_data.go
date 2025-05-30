// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	apko_build "chainguard.dev/apko/pkg/build"
)

// This is a copy of the ReleaseData related code from apko's pkg/build/sbom.go

// ParseReleaseData parses the information from /etc/os-release
//
// If no os-release file is found, it returns a Data struct with ID set to "unknown".
// TODO: this should best be imported from apko, but right now this function is not
// exported and not ready to be used outside of apko.
func ParseReleaseData(osRelease io.Reader) (*apko_build.ReleaseData, error) {
	scanner := bufio.NewScanner(osRelease)

	kv := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		before, after, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid os-release line: %q", line)
		}

		kv[before] = strings.Trim(after, "\"")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}

	return &apko_build.ReleaseData{
		ID:         kv["ID"],
		Name:       kv["NAME"],
		PrettyName: kv["PRETTY_NAME"],
		VersionID:  kv["VERSION_ID"],
	}, nil
}
