// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package util

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/melange/pkg/logger"
)

// SourceDateEpoch parses the SOURCE_DATE_EPOCH environment variable.
// If it is not set, it returns the defaultTime.
// If it is set, it MUST be an ASCII representation of an integer.
// If it is malformed, it returns an error.
func SourceDateEpoch(defaultTime time.Time) (time.Time, error) {
	return SourceDateEpochWithLogger(logger.NopLogger{}, defaultTime)
}

// SourceDateEpochWithLogger is the same as SourceDateEpoch but will log warning messages
// to the provided logger.
func SourceDateEpochWithLogger(l log.Logger, defaultTime time.Time) (time.Time, error) {
	v := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if v == "" {
		l.Warnf("SOURCE_DATE_EPOCH is specified but empty, setting it to %v", defaultTime)
		return defaultTime, nil
	}

	// The value MUST be an ASCII representation of an integer
	// with no fractional component, identical to the output
	// format of date +%s.
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		// If the value is malformed, the build process
		// SHOULD exit with a non-zero error code.
		return defaultTime, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
	}

	return time.Unix(sec, 0), nil
}
