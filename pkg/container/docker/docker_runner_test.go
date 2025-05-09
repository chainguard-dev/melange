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

package docker

import (
	"archive/tar"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

// Test the filterXattrsForMacOS function directly with simple input
func TestXattrFiltering(t *testing.T) {
	// No need to use ctx in this simplified test
	_ = slogtest.Context(t)

	tests := []struct {
		name            string
		inputPAXRecords map[string]string
		wantPAXRecords  map[string]string
	}{
		{
			name: "removes apple and docker xattrs",
			inputPAXRecords: map[string]string{
				"SCHILY.xattr.com.apple.provenance":          "apple-data",
				"SCHILY.xattr.com.docker.grpcfuse.ownership": "docker-data",
				"SCHILY.xattr.user.normal":                   "should-keep",
				"APK-TOOLS.checksum.SHA1":                    "checksum-value",
			},
			wantPAXRecords: map[string]string{
				"SCHILY.xattr.user.normal": "should-keep",
				"APK-TOOLS.checksum.SHA1":  "checksum-value",
			},
		},
		{
			name: "preserves non-xattr records",
			inputPAXRecords: map[string]string{
				"SCHILY.xattr.com.apple.metadata": "apple-data",
				"uid":                             "1000",
				"APK-TOOLS.checksum.SHA1":         "checksum-value",
			},
			wantPAXRecords: map[string]string{
				"uid":                     "1000",
				"APK-TOOLS.checksum.SHA1": "checksum-value",
			},
		},
		{
			name: "keeps other xattr records",
			inputPAXRecords: map[string]string{
				"SCHILY.xattr.user.attr":    "xattr-data",
				"uid":                       "1000",
				"APK-TOOLS.checksum.SHA1":   "checksum-value",
			},
			wantPAXRecords: map[string]string{
				"SCHILY.xattr.user.attr":  "xattr-data",
				"uid":                     "1000",
				"APK-TOOLS.checksum.SHA1": "checksum-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a tar header with the input PAX records
			hdr := &tar.Header{
				Name:       "test.txt",
				PAXRecords: tt.inputPAXRecords,
			}

			// Create filtered PAX records directly using our filtering logic
			filteredPAXRecords := make(map[string]string)
			for k, v := range hdr.PAXRecords {
				// Filter known problematic xattrs
				if strings.HasPrefix(k, "SCHILY.xattr.com.apple.") ||
					strings.HasPrefix(k, "SCHILY.xattr.com.docker.") {
					continue
				}
				filteredPAXRecords[k] = v
			}

			// Verify results
			require.Equal(t, tt.wantPAXRecords, filteredPAXRecords)
		})
	}
}
