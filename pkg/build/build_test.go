// Copyright 2022 Chainguard, Inc.
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
	"io/ioutil"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-cmp/cmp"
)

const defaultTemplateYaml = `package:
  name: nginx
  version: 100
  test: ${{package.name}}
`

const templatized = `package:
  name: [[ .Package ]]
  version: [[ .Version ]]
  test: ${{package.name}}
`

func TestApplyTemplate(t *testing.T) {
	tests := []struct {
		description string
		contents    string
		template    string
		expected    string
		shouldErr   bool
	}{
		{
			description: "no template",
			contents:    defaultTemplateYaml,
			expected:    defaultTemplateYaml,
		}, {
			description: "valid template",
			contents:    templatized,
			template:    `{"Package": "nginx", "Version": 100}`,
			expected:    defaultTemplateYaml,
		}, {
			description: "incomplete template",
			contents:    templatized,
			template:    `{"Package": "nginx"}`,
			shouldErr:   true,
		}, {
			description: "invalid template",
			contents:    templatized,
			template:    `{"Package": "nginx", "Version": 100`,
			shouldErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			actual, err := applyTemplate([]byte(test.contents), test.template)
			if err != nil && test.shouldErr {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(string(actual), test.expected); d != "" {
				t.Fatalf("actual didn't match expected: %s", d)
			}
		})
	}
}

func TestLoadConfiguration(t *testing.T) {
	expected := &Configuration{
		Package: Package{Name: "nginx", Version: "100"},
	}
	expected.Environment.Accounts.Users = []apko_types.User{{
		UserName: "build",
		UID:      1000,
		GID:      1000,
	}}
	expected.Environment.Accounts.Groups = []apko_types.Group{{
		GroupName: "build",
		GID:       1000,
		Members:   []string{"build"},
	}}

	tests := []struct {
		description string
		contents    string
		template    string
		expected    *Configuration
		shouldErr   bool
	}{
		{
			description: "no template",
			contents:    defaultTemplateYaml,
			expected:    expected,
		}, {
			description: "valid template",
			contents:    templatized,
			template:    `{"Package": "nginx", "Version": 100}`,
			expected:    expected,
		}, {
			description: "incomplete template",
			contents:    templatized,
			template:    `{"Package": "nginx"}`,
			shouldErr:   true,
		}, {
			description: "invalid template",
			contents:    templatized,
			template:    `{"Hello": "world"}`,
			shouldErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			dir := t.TempDir()
			f := filepath.Join(dir, "config")
			if err := ioutil.WriteFile(f, []byte(test.contents), 0755); err != nil {
				t.Fatal(err)
			}

			cfg := &Configuration{}
			err := cfg.Load(f, test.template)
			if test.shouldErr && err == nil {
				t.Fatal("expected test to fail but it passed")
			}
			if test.shouldErr {
				return
			}
			if d := cmp.Diff(cfg, test.expected); d != "" {
				t.Fatalf("actual didn't match expected: %s", d)
			}
		})
	}
}
