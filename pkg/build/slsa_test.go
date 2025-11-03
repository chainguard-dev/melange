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

package build

import (
	"encoding/json"
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

func TestGenerateSLSA(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		version     string
		epoch       uint64
		dataHash    string
		wantSubject string
	}{
		{
			name:        "basic package",
			packageName: "test-package",
			version:     "1.0.0",
			epoch:       0,
			dataHash:    "abcdef1234567890",
			wantSubject: "test-package-1.0.0-r0.apk",
		},
		{
			name:        "package with epoch",
			packageName: "test-package",
			version:     "1.2.3",
			epoch:       5,
			dataHash:    "abcdef1234567890",
			wantSubject: "test-package-1.2.3-r5.apk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startTime := time.Now().Add(-time.Hour)
			endTime := time.Now()

			packageBuild := &PackageBuild{
				Build: &Build{
					Configuration: &config.Configuration{
						Package: config.Package{
							Name:    tt.packageName,
							Version: tt.version,
							Epoch:   tt.epoch,
						},
					},
					Start: startTime,
					End:   endTime,
				},
				PackageName: tt.packageName,
				Origin: &config.Package{
					Name:    tt.packageName,
					Version: tt.version,
					Epoch:   tt.epoch,
				},
				DataHash: tt.dataHash,
			}

			result, err := packageBuild.generateSLSA()
			require.NoError(t, err)
			require.NotEmpty(t, result)

			var statement intoto.Statement
			err = json.Unmarshal(result, &statement)
			require.NoError(t, err)

			require.Equal(t, "https://in-toto.io/Statement/v1", statement.Type)
			require.Equal(t, slsaProvenanceStatementType, statement.PredicateType)
			require.Len(t, statement.Subject, 1)
			require.Equal(t, tt.wantSubject, statement.Subject[0].Name)
			require.Equal(t, tt.dataHash, statement.Subject[0].Digest["sha256"])

			require.NotNil(t, statement.Predicate)

			resultStr := string(result)
			require.Contains(t, resultStr, melangeBuilder)
			require.Contains(t, resultStr, melangeBuildType)
			require.Contains(t, resultStr, tt.packageName)
		})
	}
}

func TestGenerateSLSAValidJSON(t *testing.T) {
	packageBuild := &PackageBuild{
		Build: &Build{
			Configuration: &config.Configuration{
				Package: config.Package{
					Name:    "json-test",
					Version: "1.0.0",
					Epoch:   0,
				},
			},
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		PackageName: "json-test",
		Origin: &config.Package{
			Name:    "json-test",
			Version: "1.0.0",
			Epoch:   0,
		},
		DataHash: "sha256hash",
	}

	result, err := packageBuild.generateSLSA()
	require.NoError(t, err)

	var jsonObj map[string]any
	err = json.Unmarshal(result, &jsonObj)
	require.NoError(t, err)

	require.Contains(t, jsonObj, "type")
	require.Contains(t, jsonObj, "predicate_type")
	require.Contains(t, jsonObj, "subject")
	require.Contains(t, jsonObj, "predicate")
}
