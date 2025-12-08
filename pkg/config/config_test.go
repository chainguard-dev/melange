package config

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/sbom"
)

func Test_validateCPE(t *testing.T) {
	cases := []struct {
		name    string
		cpe     CPE
		wantErr bool
	}{
		{
			name:    "minimally valid",
			cpe:     CPE{Vendor: "b", Product: "c"},
			wantErr: false,
		},
		{
			name:    "product without vendor",
			cpe:     CPE{Product: "c"},
			wantErr: true,
		},
		{
			name:    "vendor without product",
			cpe:     CPE{Vendor: "b"},
			wantErr: true,
		},
		{
			name:    "valid with additional fields set",
			cpe:     CPE{Part: "a", Vendor: "b", Product: "c", TargetSW: "d", TargetHW: "e"},
			wantErr: false,
		},
		{
			name:    "invalid part",
			cpe:     CPE{Part: "h", Vendor: "b", Product: "c"},
			wantErr: true,
		},
		{
			name:    "invalid characters",
			cpe:     CPE{Vendor: "b", Product: "c:5"},
			wantErr: true,
		},
		{
			name:    "more invalid characters",
			cpe:     CPE{Vendor: "B!", Product: "c"},
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCPE(tt.cpe)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_applySubstitution(t *testing.T) {
	ctx := slogtest.Context(t)

	fp := filepath.Join(os.TempDir(), "melange-test-applySubstitutionsInProvides")
	if err := os.WriteFile(fp, []byte(`
package:
  name: replacement-provides
  version: 0.0.1
  epoch: 7
  description: example using a replacement in provides
  dependencies:
    runtime:
      - ${{package.name}}-config
      - ${{vars.bar}}
      - other-package=${{package.version}}
    provides:
      - replacement-provides-version=${{package.version}}
      - replacement-provides-foo=${{vars.foo}}
      - replacement-provides-bar=${{vars.bar}}
      - replacement-provides=${{package.full-version}}

environment:
  contents:
    packages:
      - dep~${{package.version}}

vars:
  foo: FOO
  bar: BAR

var-transforms:
  - from: ${{package.version}}
    match: ^(\d+\.\d+)\.\d+$
    replace: "$1"
    to: short-package-version

subpackages:
  - name: subpackage-${{vars.short-package-version}}
    dependencies:
      runtime:
        - ${{package.name}}-config-${{package.version}}
        - ${{vars.foo}}
        - other-package=${{package.version}}
        - replacement-provides-${{vars.short-package-version}}
      provides:
        - subpackage-version=${{package.version}}
        - subpackage-foo=${{vars.foo}}
        - subpackage-bar=${{vars.bar}}
      replaces:
        - james=${{package.name}}
    test:
      pipeline:
        - runs: echo "${{subpkg.name}} test case"
        - runs: echo "context.name=${{context.name}}"

test:
  environment:
    contents:
      packages:
        - ${{package.name}}-config
        - replacement-provides-${{vars.short-package-version}}
    environment:
      LD_LIBRARY_PATH: "/usr/local/${{vars.foo}}"
  pipeline:
    - runs: "echo context.name=${{context.name}}"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}
	require.Equal(t, []string{
		"replacement-provides-version=0.0.1",
		"replacement-provides-foo=FOO",
		"replacement-provides-bar=BAR",
		"replacement-provides=0.0.1-r7",
	}, cfg.Package.Dependencies.Provides)

	require.Equal(t, []string{
		"subpackage-version=0.0.1",
		"subpackage-foo=FOO",
		"subpackage-bar=BAR",
	}, cfg.Subpackages[0].Dependencies.Provides)

	require.Equal(t, []string{
		"replacement-provides-config",
		"BAR",
		"other-package=0.0.1",
	}, cfg.Package.Dependencies.Runtime)

	require.Equal(t, []string{
		"replacement-provides-config-0.0.1",
		"FOO",
		"other-package=0.0.1",
		"replacement-provides-0.0",
	}, cfg.Subpackages[0].Dependencies.Runtime)

	require.Equal(t, []string{
		"james=replacement-provides",
	}, cfg.Subpackages[0].Dependencies.Replaces)

	require.Equal(t, []string{
		"dep~0.0.1",
	}, cfg.Environment.Contents.Packages)

	require.Equal(t, []string{
		"replacement-provides-config",
		"replacement-provides-0.0",
	}, cfg.Test.Environment.Contents.Packages)

	require.Equal(t, cfg.Subpackages[0].Name, "subpackage-0.0")

	require.Equal(t, "/usr/local/FOO", cfg.Test.Environment.Environment["LD_LIBRARY_PATH"])
}

func Test_rangeSubstitutions(t *testing.T) {
	ctx := slogtest.Context(t)

	fp := filepath.Join(os.TempDir(), "melange-test-applySubstitutionsInProvides")
	if err := os.WriteFile(fp, []byte(`
package:
  name: range-substitutions
  version: 0.0.1
  epoch: 7
  description: example using a range in subpackages

data:
  - name: I-am-a-range
    items:
      a: A
      b: B

subpackages:
  - range: I-am-a-range
    name: ${{range.key}}
    description: ${{range.value}}
    options:
      no-provides: true
    dependencies:
      runtime:
        - wow-some-kinda-dynamically-linked-library-i-guess=1.0
    test:
      environment:
        contents:
          packages:
            - python3
            - ${{range.value}}-default-jvm
            - R
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}
	require.Equal(t, cfg.Subpackages[0].Dependencies.Runtime[0], "wow-some-kinda-dynamically-linked-library-i-guess=1.0")
	require.True(t, cfg.Subpackages[0].Options.NoProvides)
	require.Equal(t, cfg.Subpackages[0].Test.Environment.Contents.Packages[1], "A-default-jvm")
}

func Test_rangeSubstitutionsPriorities(t *testing.T) {
	ctx := slogtest.Context(t)

	fp := filepath.Join(os.TempDir(), "melange-test-applySubstitutionsInRangePriorities")
	if err := os.WriteFile(fp, []byte(`
package:
  name: range-substitutions
  version: 0.0.1
  epoch: 7
  description: example using a range in subpackages

data:
  - name: I-am-a-range
    items:
      a: 10
      b: 20

vars:
  buildLocation: "/home/build/foo"

subpackages:
  - range: I-am-a-range
    name: ${{range.key}}
    description: Check priorities are ${{range.value}}
    dependencies:
      provider-priority: ${{range.value}}
      replaces-priority: ${{range.value}}
      runtime:
        - wow-some-kinda-dynamically-linked-library-i-guess=1.0
    pipeline:
      - needs:
          packages:
            - ${{range.key}}
        working-directory: ${{vars.buildLocation}}/subdir/${{range.key}}/${{range.value}}
        runs: |
          echo "$PWD"
        pipeline:
          - runs: exit 1
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}
	require.Equal(t, cfg.Subpackages[0].Dependencies.ProviderPriority, "10")
	require.Equal(t, cfg.Subpackages[0].Dependencies.ReplacesPriority, "10")
	require.Equal(t, cfg.Subpackages[0].Pipeline[0].WorkDir, "/home/build/foo/subdir/a/10")
	require.Equal(t, cfg.Subpackages[1].Pipeline[0].WorkDir, "/home/build/foo/subdir/b/20")
	require.Equal(t, cfg.Subpackages[0].Pipeline[0].Needs.Packages[0], "a")
	require.Equal(t, cfg.Subpackages[1].Pipeline[0].Needs.Packages[0], "b")
	require.Equal(t, cfg.Subpackages[0].Pipeline[0].Pipeline[0].Runs, "exit 1")
	require.Equal(t, cfg.Subpackages[1].Pipeline[0].Pipeline[0].Runs, "exit 1")
}

func Test_propagatePipelines(t *testing.T) {
	ctx := slogtest.Context(t)

	fp := filepath.Join(os.TempDir(), "melange-test-propagatePipelines")
	if err := os.WriteFile(fp, []byte(`
package:
  name: propagate-pipelines
  version: 0.0.1
  epoch: 1
  description: example testing propagation of child pipelines

pipeline:
  - environment:
      foo: FOO
      bar: BAR
    pipeline:
      - environment:
          foo: BAR
          baz: BAZ

subpackages:
  - name: subpackage
    pipeline:
    - environment:
        foo: FOO
        bar: BAR
      pipeline:
      - environment:
          foo: BAR
          baz: BAZ
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}

	require.Equal(t, map[string]string{"foo": "FOO", "bar": "BAR"}, cfg.Pipeline[0].Environment)
	require.Equal(t, map[string]string{"foo": "BAR", "bar": "BAR", "baz": "BAZ"}, cfg.Pipeline[0].Pipeline[0].Environment)
	require.Equal(t, map[string]string{"foo": "FOO", "bar": "BAR"}, cfg.Subpackages[0].Pipeline[0].Environment)
	require.Equal(t, map[string]string{"foo": "BAR", "bar": "BAR", "baz": "BAZ"}, cfg.Subpackages[0].Pipeline[0].Pipeline[0].Environment)
}

func Test_propagateWorkingDirectory(t *testing.T) {
	ctx := slogtest.Context(t)
	fp := filepath.Join(os.TempDir(), "melange-test-propagateWorkingDirectory")
	if err := os.WriteFile(fp, []byte(`
package:
  name: propagate-workdir
  version: 0.0.1
  epoch: 1
  description: example testing propagation of working directory

pipeline:
  - working-directory: /home/build/foo
    pipeline:
      - runs: pwd

  - working-directory: /home/build/bar
    pipeline:
      - working-directory: /home/build/baz
        pipeline:
          - runs: pwd
          - runs: pwd
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}

	require.Equal(t, "/home/build/foo", cfg.Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/foo", cfg.Pipeline[0].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/bar", cfg.Pipeline[1].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].Pipeline[1].WorkDir)
}

func Test_propagateWorkingDirectoryToUsesNodes(t *testing.T) {
	ctx := slogtest.Context(t)
	fp := filepath.Join(os.TempDir(), "melange-test-propagateWorkingDirectory")
	if err := os.WriteFile(fp, []byte(`
package:
  name: propagate-workdir
  version: 0.0.1
  epoch: 1
  description: example testing propagation of working directory

pipeline:
  - working-directory: /home/build/foo
    pipeline:
      - runs: pwd

  - working-directory: /home/build/bar
    pipeline:
      - working-directory: /home/build/baz
        pipeline:
          - runs: pwd
          - runs: pwd
          - uses: fetch
            with:
              uri: https://example.com/foo-${{package.version}}.zip
              expected-sha256: 123456
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}

	require.Equal(t, "/home/build/foo", cfg.Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/foo", cfg.Pipeline[0].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/bar", cfg.Pipeline[1].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].Pipeline[0].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].Pipeline[1].WorkDir)
	require.Equal(t, "/home/build/baz", cfg.Pipeline[1].Pipeline[0].Pipeline[2].WorkDir)
	require.Equal(t, "https://example.com/foo-0.0.1.zip", cfg.Pipeline[1].Pipeline[0].Pipeline[2].With["uri"])
}

func Test_packageAnnotations(t *testing.T) {
	ctx := slogtest.Context(t)
	fp := filepath.Join(os.TempDir(), "melange-test-packageAnnotations")
	if err := os.WriteFile(fp, []byte(`
package:
  name: annotations-workdir
  version: 0.0.1
  epoch: 1
  annotations:
    cgr.dev/ecosystem: python

`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}

	require.Equal(t, "python", cfg.Package.Annotations["cgr.dev/ecosystem"])
}

func TestDuplicateSubpackage(t *testing.T) {
	ctx := slogtest.Context(t)

	fp := filepath.Join(os.TempDir(), "melange-test-applySubstitutionsInProvides")
	if err := os.WriteFile(fp, []byte(`
package:
  name: dupe-subpackage
  version: 0.0.1
  epoch: 8
  description: example using a two subpackages with same name

data:
  - name: I-am-a-range
    items:
      a: ""
      b: ""

subpackages:
  - name: subpackage
    range: I-am-a-range
    pipeline:
      - runs: echo "I am a subpackage for ${{range.key}"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfiguration(ctx, fp); err == nil {
		t.Errorf("configuration should have failed to validate, got: %v", err)
	}
}

func TestValidatePipelines(t *testing.T) {
	tests := []struct {
		name    string
		p       []Pipeline
		wantErr bool
	}{
		{
			name: "valid pipeline with uses",
			p: []Pipeline{
				{Uses: "build", With: map[string]string{"param": "value"}},
			},
			wantErr: false,
		},
		{
			name: "invalid pipeline with with but no uses",
			p: []Pipeline{
				{With: map[string]string{"param": "value"}},
			},
			wantErr: true,
		},
		{
			name: "invalid pipeline with both uses and runs",
			p: []Pipeline{
				{Uses: "deploy", Runs: "somescript.sh"},
			},
			wantErr: true,
		},
		{
			name: "invalid pipeline with both with and runs",
			p: []Pipeline{
				{Runs: "somescript.sh", With: map[string]string{"param": "value"}},
			},
			wantErr: true,
		},

		{
			name: "invalid pipeline with both uses and pipeline",
			p: []Pipeline{
				{Uses: "deploy", Pipeline: []Pipeline{{Runs: "somescript.sh"}}},
			},
			wantErr: false, // only a warning.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			err := validatePipelines(ctx, tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePipelines() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetScheduleMessage(t *testing.T) {
	tests := []struct {
		schedule Schedule
		expected string
		err      bool
	}{
		{Schedule{Period: Daily}, "Scheduled daily update check", false},
		{Schedule{Period: Weekly}, "Scheduled weekly update check", false},
		{Schedule{Period: Monthly}, "Scheduled monthly update check", false},
		{Schedule{Period: "yearly"}, "", true},
	}

	for _, test := range tests {
		result, err := test.schedule.GetScheduleMessage()
		if (err != nil) != test.err {
			t.Errorf("GetScheduleMessage(%v) returned error %v, expected error: %v", test.schedule, err, test.err)
		}
		if result != test.expected {
			t.Errorf("GetScheduleMessage(%v) = %v, expected %v", test.schedule, result, test.expected)
		}
	}
}

func TestGetGitSBOMPackage(t *testing.T) {
	testCases := []struct {
		name            string
		repo            string
		tag             string
		expectedCommit  string
		idComponents    []string
		licenseDeclared string
		typeHint        string
		supplier        string
		expected        *sbom.Package
		expectError     bool
	}{
		{
			name:            "github repo with tag",
			repo:            "https://github.com/chainguard-dev/melange",
			tag:             "v1.0.0",
			expectedCommit:  "",
			idComponents:    []string{"test-id"},
			licenseDeclared: "Apache-2.0",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "melange",
				Version:          "v1.0.0",
				LicenseDeclared:  "Apache-2.0",
				Namespace:        "chainguard-dev",
				PURL:             &purl.PackageURL{Type: "github", Namespace: "chainguard-dev", Name: "melange", Version: "v1.0.0"},
				DownloadLocation: "https://github.com/chainguard-dev/melange/archive/v1.0.0.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "github repo with commit",
			repo:            "https://github.com/chainguard-dev/melange",
			tag:             "",
			expectedCommit:  "b5d6dcba7c835d8520b06c7f35e747d896c50b61",
			idComponents:    []string{"test-id"},
			licenseDeclared: "Apache-2.0",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "melange",
				Version:          "b5d6dcba7c835d8520b06c7f35e747d896c50b61",
				LicenseDeclared:  "Apache-2.0",
				Namespace:        "chainguard-dev",
				PURL:             &purl.PackageURL{Type: "github", Namespace: "chainguard-dev", Name: "melange", Version: "b5d6dcba7c835d8520b06c7f35e747d896c50b61"},
				DownloadLocation: "https://github.com/chainguard-dev/melange/archive/b5d6dcba7c835d8520b06c7f35e747d896c50b61.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "github repo with both tag and commit",
			repo:            "https://github.com/chainguard-dev/melange",
			tag:             "v1.0.0",
			expectedCommit:  "b5d6dcba7c835d8520b06c7f35e747d896c50b61",
			idComponents:    []string{"test-id"},
			licenseDeclared: "Apache-2.0",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "melange",
				Version:          "v1.0.0",
				LicenseDeclared:  "Apache-2.0",
				Namespace:        "chainguard-dev",
				PURL:             &purl.PackageURL{Type: "github", Namespace: "chainguard-dev", Name: "melange", Version: "v1.0.0"},
				DownloadLocation: "https://github.com/chainguard-dev/melange/archive/b5d6dcba7c835d8520b06c7f35e747d896c50b61.tar.gz",
			},
			expectError: false,
			typeHint:    "",
		},
		{
			name:            "gitlab.com repo with tag",
			repo:            "https://gitlab.com/gitlab-org/gitlab",
			tag:             "v15.11.0",
			expectedCommit:  "",
			idComponents:    []string{"test-id"},
			licenseDeclared: "MIT",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "gitlab",
				Version:          "v15.11.0",
				LicenseDeclared:  "MIT",
				Namespace:        "gitlab-org",
				PURL:             &purl.PackageURL{Type: "gitlab", Namespace: "gitlab-org", Name: "gitlab", Version: "v15.11.0"},
				DownloadLocation: "https://gitlab.com/gitlab-org/gitlab/-/archive/v15.11.0/v15.11.0.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "gitlab.com repo with commit",
			repo:            "https://gitlab.com/gitlab-org/gitlab",
			tag:             "",
			expectedCommit:  "dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a",
			idComponents:    []string{"test-id"},
			licenseDeclared: "MIT",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "gitlab",
				Version:          "dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a",
				LicenseDeclared:  "MIT",
				Namespace:        "gitlab-org",
				PURL:             &purl.PackageURL{Type: "gitlab", Namespace: "gitlab-org", Name: "gitlab", Version: "dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a"},
				DownloadLocation: "https://gitlab.com/gitlab-org/gitlab/-/archive/dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a/dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "gitlab.com repo with both tag and commit",
			repo:            "https://gitlab.com/gitlab-org/gitlab",
			tag:             "v15.11.0",
			expectedCommit:  "dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a",
			idComponents:    []string{"test-id"},
			licenseDeclared: "MIT",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:     []string{"test-id"},
				Name:             "gitlab",
				Version:          "v15.11.0",
				LicenseDeclared:  "MIT",
				Namespace:        "gitlab-org",
				PURL:             &purl.PackageURL{Type: "gitlab", Namespace: "gitlab-org", Name: "gitlab", Version: "v15.11.0"},
				DownloadLocation: "https://gitlab.com/gitlab-org/gitlab/-/archive/dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a/dd88f2ad62eeb81cf3562eb8284e3c97d3e94a8a.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "custom gitlab instance with tag",
			repo:            "https://gitlab.foo.bar/some-org/some-project",
			tag:             "v2.3.4",
			expectedCommit:  "",
			idComponents:    []string{"test-id"},
			licenseDeclared: "BSD-3-Clause",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "some-project",
				Version:         "v2.3.4",
				LicenseDeclared: "BSD-3-Clause",
				Namespace:       "some-org",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "some-project",
					Version:    "v2.3.4",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://gitlab.foo.bar/some-org/some-project"}),
				},
				DownloadLocation: "https://gitlab.foo.bar/some-org/some-project/-/archive/v2.3.4/v2.3.4.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "custom gitlab instance with commit",
			repo:            "https://gitlab.foo.bar/some-org/some-project",
			tag:             "",
			expectedCommit:  "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
			idComponents:    []string{"test-id"},
			licenseDeclared: "BSD-3-Clause",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "some-project",
				Version:         "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
				LicenseDeclared: "BSD-3-Clause",
				Namespace:       "some-org",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "some-project",
					Version:    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://gitlab.foo.bar/some-org/some-project@1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"}),
				},
				DownloadLocation: "https://gitlab.foo.bar/some-org/some-project/-/archive/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "custom gitlab instance with both tag and commit",
			repo:            "https://gitlab.foo.bar/some-org/some-project",
			tag:             "v2.3.4",
			expectedCommit:  "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
			idComponents:    []string{"test-id"},
			licenseDeclared: "BSD-3-Clause",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "some-project",
				Version:         "v2.3.4",
				LicenseDeclared: "BSD-3-Clause",
				Namespace:       "some-org",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "some-project",
					Version:    "v2.3.4",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://gitlab.foo.bar/some-org/some-project@1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"}),
				},
				DownloadLocation: "https://gitlab.foo.bar/some-org/some-project/-/archive/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "undentifiable gitlab instance with both tag and commit",
			repo:            "https://code.videolan.org/videolan/dav1d",
			tag:             "1.5.1",
			expectedCommit:  "42b2b24fb8819f1ed3643aa9cf2a62f03868e3aa",
			idComponents:    []string{"test-id"},
			licenseDeclared: "BSD-3-Clause",
			typeHint:        "gitlab",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "dav1d",
				Version:         "1.5.1",
				LicenseDeclared: "BSD-3-Clause",
				Namespace:       "videolan",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "dav1d",
					Version:    "1.5.1",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://code.videolan.org/videolan/dav1d@42b2b24fb8819f1ed3643aa9cf2a62f03868e3aa"}),
				},
				DownloadLocation: "https://code.videolan.org/videolan/dav1d/-/archive/42b2b24fb8819f1ed3643aa9cf2a62f03868e3aa/42b2b24fb8819f1ed3643aa9cf2a62f03868e3aa.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "generic git repo with tag",
			repo:            "https://git.example.com/custom-org/custom-project",
			tag:             "v3.2.1",
			expectedCommit:  "",
			idComponents:    []string{"test-id"},
			licenseDeclared: "LGPL-2.1",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "custom-org/custom-project",
				Version:         "v3.2.1",
				LicenseDeclared: "LGPL-2.1",
				Namespace:       "wolfi",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "custom-org/custom-project",
					Version:    "v3.2.1",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://git.example.com/custom-org/custom-project"}),
				},
				DownloadLocation: "https://tarballs.cgr.dev/c/96d75acab51420a1b54afcc15734f3c5e67aee89a2e73f226000bc308ff09789-v3.2.1.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "generic git repo with commit",
			repo:            "https://git.example.com/custom-org/custom-project",
			tag:             "",
			expectedCommit:  "abcdef0123456789abcdef0123456789abcdef01",
			idComponents:    []string{"test-id"},
			licenseDeclared: "LGPL-2.1",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "custom-org/custom-project",
				Version:         "abcdef0123456789abcdef0123456789abcdef01",
				LicenseDeclared: "LGPL-2.1",
				Namespace:       "wolfi",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "custom-org/custom-project",
					Version:    "abcdef0123456789abcdef0123456789abcdef01",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://git.example.com/custom-org/custom-project@abcdef0123456789abcdef0123456789abcdef01"}),
				},
				DownloadLocation: "https://tarballs.cgr.dev/c/96d75acab51420a1b54afcc15734f3c5e67aee89a2e73f226000bc308ff09789-abcdef0123456789abcdef0123456789abcdef01.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "generic git repo with both tag and commit",
			repo:            "https://git.example.com/custom-org/custom-project",
			tag:             "v3.2.1",
			expectedCommit:  "abcdef0123456789abcdef0123456789abcdef01",
			idComponents:    []string{"test-id"},
			licenseDeclared: "LGPL-2.1",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "custom-org/custom-project",
				Version:         "v3.2.1",
				LicenseDeclared: "LGPL-2.1",
				Namespace:       "wolfi",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "custom-org/custom-project",
					Version:    "v3.2.1",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git+https://git.example.com/custom-org/custom-project@abcdef0123456789abcdef0123456789abcdef01"}),
				},
				DownloadLocation: "https://tarballs.cgr.dev/c/96d75acab51420a1b54afcc15734f3c5e67aee89a2e73f226000bc308ff09789-abcdef0123456789abcdef0123456789abcdef01.tar.gz",
			},
			expectError: false,
		},
		{
			name:            "generic git repo with git scheme with both tag and commit",
			repo:            "git://git.example.com/custom-project",
			tag:             "v3.2.1",
			expectedCommit:  "abcdef0123456789abcdef0123456789abcdef01",
			idComponents:    []string{"test-id"},
			licenseDeclared: "LGPL-2.1",
			typeHint:        "",
			supplier:        "wolfi",
			expected: &sbom.Package{
				IDComponents:    []string{"test-id"},
				Name:            "custom-project",
				Version:         "v3.2.1",
				LicenseDeclared: "LGPL-2.1",
				Namespace:       "wolfi",
				PURL: &purl.PackageURL{
					Type:       "generic",
					Name:       "custom-project",
					Version:    "v3.2.1",
					Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": "git://git.example.com/custom-project@abcdef0123456789abcdef0123456789abcdef01"}),
				},
				DownloadLocation: "https://tarballs.cgr.dev/c/a37e698130227f6921f1963616a45dc5337f7249cc00c53e6b80f5a44bf01fd7-abcdef0123456789abcdef0123456789abcdef01.tar.gz",
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, err := getGitSBOMPackage(tc.repo, tc.tag, tc.expectedCommit, tc.idComponents, tc.licenseDeclared, tc.typeHint, tc.supplier)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pkg)

			// Using require.Equal for PURL separately because its fields may need special comparison
			require.Equal(t, tc.expected.PURL.Type, pkg.PURL.Type)
			require.Equal(t, tc.expected.PURL.Namespace, pkg.PURL.Namespace)
			require.Equal(t, tc.expected.PURL.Name, pkg.PURL.Name)
			require.Equal(t, tc.expected.PURL.Version, pkg.PURL.Version)
			if tc.expected.PURL.Qualifiers != nil {
				require.Equal(t, tc.expected.PURL.Qualifiers, pkg.PURL.Qualifiers)
			}

			// Compare other fields
			require.Equal(t, tc.expected.Name, pkg.Name)
			require.Equal(t, tc.expected.Version, pkg.Version)
			require.Equal(t, tc.expected.LicenseDeclared, pkg.LicenseDeclared)
			require.Equal(t, tc.expected.Namespace, pkg.Namespace)
			require.Equal(t, tc.expected.DownloadLocation, pkg.DownloadLocation)
		})
	}
}

func TestSetCap(t *testing.T) {
	tests := []struct {
		setcap []Capability
		err    bool
	}{
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_net_bind_service": "+eip"},
					Reason: "Needed for package foo because xyz",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_net_raw": "+eip"},
					Reason: "Needed for package baz because xyz",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_net_raw,cap_net_admin,cap_net_bind_service": "+ep"},
					Reason: "Valid combination of three capabilities on a single line",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path: "/bar",
					Add: map[string]string{
						"cap_net_raw":          "+ep",
						"cap_net_admin":        "+ep",
						"cap_net_bind_service": "+ep",
					},
					Reason: "Valid combination of three capabilities on separate lines",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path: "/foo",
					Add: map[string]string{
						"cap_net_raw": "+ep",
					},
					Reason: "First package in a multi-package, multi-capability capability addition.",
				},
				{
					Path: "/bar",
					Add: map[string]string{
						"cap_net_admin":        "+ep",
						"cap_net_bind_service": "+ep",
					},
					Reason: "Second package in a multi-package, multi-capability capability addition.",
				},
				{
					Path: "/baz",
					Add: map[string]string{
						"cap_net_raw,cap_net_admin,cap_net_bind_service": "+eip",
					},
					Reason: "Third package in a multi-package, multi-capability capability addition.",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path: "/foo",
					Add: map[string]string{
						"cap_net_raw": "+ep",
					},
					Reason: "First package in a multi-package, multi-capability capability addition.",
				},
				{
					Path: "/bar",
					Add: map[string]string{
						"cap_setfcap":          "+ep",
						"cap_net_bind_service": "+ep",
					},
					Reason: "Tying to sneak an invalid capability into multiple paths.",
				},
				{
					Path: "/baz",
					Add: map[string]string{
						"cap_net_raw,cap_net_admin,cap_net_bind_service": "+eip",
					},
					Reason: "Third package in a multi-package, multi-capability capability addition.",
				},
			},
			true,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_sys_admin": "+ep"},
					Reason: "Needed for package baz",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_ipc_lock": "+ep"},
					Reason: "Needed for package baz",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_net_admin": "+ep"},
					Reason: "Needed for package baz",
				},
			},
			false,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_net_admin": "+ep"},
					Reason: "",
				},
			},
			true,
		},
		{
			[]Capability{
				{
					Path:   "/bar",
					Add:    map[string]string{"cap_setfcap": "+ep"},
					Reason: "I want to arbitrarily set capabilities",
				},
			},
			true,
		},
	}

	for _, test := range tests {
		err := validateCapabilities(test.setcap)
		if (err != nil) != test.err {
			t.Errorf("validateCapabilities(%v) returned error %v, expected error: %v", test.setcap, err, test.err)
		}
	}
}

// Mock resources to test setcap capabilities
type mockFS struct {
	xattrs map[string]map[string][]byte
}

func newMockFS() *mockFS {
	return &mockFS{
		xattrs: make(map[string]map[string][]byte),
	}
}

func (fs *mockFS) SetXattr(path, attr string, value []byte) error {
	if _, ok := fs.xattrs[path]; !ok {
		fs.xattrs[path] = make(map[string][]byte)
	}
	fs.xattrs[path][attr] = value
	return nil
}

func (fs *mockFS) GetXattr(path, attr string) ([]byte, error) {
	if attrs, ok := fs.xattrs[path]; ok {
		if value, ok := attrs[attr]; ok {
			return value, nil
		}
	}
	return nil, os.ErrNotExist
}

func TestSetCapability(t *testing.T) {
	type Config struct {
		Package struct {
			SetCap []Capability
		}
	}

	type Builder struct {
		Configuration  Config
		WorkspaceDirFS *mockFS
	}

	testCases := []struct {
		name          string
		caps          []Capability
		expectedAttrs map[string]map[string][]byte
	}{
		{
			name: "Basic capability +ep",
			caps: []Capability{
				{
					Path: "/usr/bin/fping",
					Add: map[string]string{
						"cap_net_raw": "+ep",
					},
					Reason: "foo",
				},
			},
			expectedAttrs: map[string]map[string][]byte{
				"/usr/bin/fping": {
					"security.capability": nil,
				},
			},
		},
		{
			name: "Multiple capabilities",
			caps: []Capability{
				{
					Path: "/usr/bin/traceroute",
					Add: map[string]string{
						"cap_net_raw":   "+ep",
						"cap_net_admin": "+eip",
					},
					Reason: "foo",
				},
			},
			expectedAttrs: map[string]map[string][]byte{
				"/usr/bin/traceroute": {
					"security.capability": nil,
				},
			},
		},
		{
			name: "Multiple paths",
			caps: []Capability{
				{
					Path: "/bin/ping",
					Add: map[string]string{
						"cap_net_raw": "+ep",
					},
					Reason: "foo",
				},
				{
					Path: "/usr/bin/traceroute",
					Add: map[string]string{
						"cap_net_admin": "+eip",
					},
					Reason: "foo",
				},
			},
			expectedAttrs: map[string]map[string][]byte{
				"/bin/ping": {
					"security.capability": nil,
				},
				"/usr/bin/traceroute": {
					"security.capability": nil,
				},
			},
		},
		{
			name: "Single-line capabilities with same flags",
			caps: []Capability{
				{
					Path: "/bin/custom-tool",
					Add: map[string]string{
						"cap_net_raw,cap_net_admin": "+ep",
					},
					Reason: "foo",
				},
			},
			expectedAttrs: map[string]map[string][]byte{
				"/bin/custom-tool": {
					"security.capability": nil,
				},
			},
		},
		{
			name: "Multiple comma-separated capabilities with different flags",
			caps: []Capability{
				{
					Path: "/usr/bin/privileged-tool",
					Add: map[string]string{
						"cap_net_raw,cap_net_admin,cap_net_bind_service": "+eip",
						"cap_sys_admin": "+p",
					},
					Reason: "foo",
				},
			},
			expectedAttrs: map[string]map[string][]byte{
				"/usr/bin/privileged-tool": {
					"security.capability": nil,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Builder{
				WorkspaceDirFS: newMockFS(),
			}
			b.Configuration.Package.SetCap = tc.caps

			caps, err := ParseCapabilities(b.Configuration.Package.SetCap)
			if err != nil {
				t.Fatalf("Failed to collect capabilities: %v", err)
			}

			expectedAttrs := make(map[string][]byte)
			for path, c := range caps {
				encoded := EncodeCapability(c.Effective, c.Permitted, c.Inheritable)
				expectedAttrs[path] = encoded

				if err := b.WorkspaceDirFS.SetXattr(path, "security.capability", encoded); err != nil {
					t.Fatalf("failed to set xattr for %s: %v", path, err)
				}
			}

			for path, expected := range expectedAttrs {
				data, err := b.WorkspaceDirFS.GetXattr(path, "security.capability")
				if err != nil {
					t.Errorf("Failed to get xattr %s: %v", path, err)
					continue
				}

				if !bytes.Equal(data, expected) {
					t.Errorf("Mismatched xattr for %s:\ngot:  %x\nwant: %x", path, data, expected)
				}

				if len(data) < 24 {
					t.Errorf("Capability data too short for %s: got %d bytes", path, len(data))
					continue
				}

				magic := binary.LittleEndian.Uint32(data[0:4])
				revision := magic & 0xFF000000
				flags := magic & 0x000000FF

				if revision != 0x03000000 {
					t.Errorf("Invalid revision: %x", revision)
				}

				permitted := binary.LittleEndian.Uint32(data[4:8])
				inheritable := binary.LittleEndian.Uint32(data[8:12])
				rootid := binary.LittleEndian.Uint32(data[20:24])

				if rootid != 0 {
					t.Errorf("Unexpected rootid: %d", rootid)
				}

				effective := flags & 0x01

				for _, capEntry := range tc.caps {
					if capEntry.Path != path {
						continue
					}
					for attr, flag := range capEntry.Add {
						for a := range strings.SplitSeq(attr, ",") {
							val := getCapabilityValue(a)
							e, p, i := parseCapability(flag)

							if e && effective != 1 {
								t.Errorf("Expected effective bit set for %s", path)
							}
							if p && (permitted&val != val) {
								t.Errorf("Expected permitted cap %s in %s", a, path)
							}
							if i && (inheritable&val != val) {
								t.Errorf("Expected inheritable cap %s in %s", a, path)
							}
						}
					}
				}
			}
		})
	}
}

func TestPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		distro   string
		arch     string
		expected string
	}{
		{
			name: "basic package URL",
			pkg: Package{
				Name:    "test-package",
				Version: "1.0.0",
				Epoch:   0,
			},
			distro:   "alpine",
			arch:     "x86_64",
			expected: "pkg:apk/alpine/test-package@1.0.0-r0?arch=x86_64&distro=alpine",
		},
		{
			name: "package with epoch",
			pkg: Package{
				Name:    "test-package",
				Version: "2.1.3",
				Epoch:   5,
			},
			distro:   "wolfi",
			arch:     "aarch64",
			expected: "pkg:apk/wolfi/test-package@2.1.3-r5?arch=aarch64&distro=wolfi",
		},
		{
			name: "package without architecture",
			pkg: Package{
				Name:    "test-package",
				Version: "1.0.0",
				Epoch:   0,
			},
			distro:   "alpine",
			arch:     "",
			expected: "pkg:apk/alpine/test-package@1.0.0-r0?distro=alpine",
		},
		{
			name: "package with complex version",
			pkg: Package{
				Name:    "complex-package",
				Version: "1.2.3-alpha.1",
				Epoch:   10,
			},
			distro:   "chainguard",
			arch:     "x86_64",
			expected: "pkg:apk/chainguard/complex-package@1.2.3-alpha.1-r10?arch=x86_64&distro=chainguard",
		},
		{
			name: "package with special characters in name",
			pkg: Package{
				Name:    "lib-test_package.so",
				Version: "0.1.0",
				Epoch:   1,
			},
			distro:   "alpine",
			arch:     "arm64",
			expected: "pkg:apk/alpine/lib-test_package.so@0.1.0-r1?arch=arm64&distro=alpine",
		},
		{
			name: "package with unknown distro",
			pkg: Package{
				Name:    "lib-test_package.so",
				Version: "0.1.0",
				Epoch:   1,
			},
			distro:   "unknown",
			arch:     "arm64",
			expected: "pkg:apk/unknown/lib-test_package.so@0.1.0-r1?arch=arm64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packageURL := tt.pkg.PackageURL(tt.distro, tt.arch)
			require.NotNil(t, packageURL)

			actualURL := packageURL.String()
			require.Equal(t, tt.expected, actualURL, "PackageURL string representation should match expected format")

			// Verify the PackageURL can be parsed back
			parsed, err := purl.FromString(actualURL)
			require.NoError(t, err, "Generated PackageURL should be parseable")

			// Verify components
			require.Equal(t, purlTypeAPK, parsed.Type)
			require.Equal(t, tt.distro, parsed.Namespace)
			require.Equal(t, tt.pkg.Name, parsed.Name)
			require.Equal(t, tt.pkg.FullVersion(), parsed.Version)
		})
	}
}

func TestTestResources(t *testing.T) {
	ctx := slogtest.Context(t)

	tests := []struct {
		name                string
		yaml                string
		expectResources     *Resources
		expectTestResources *Resources
		expectParseError    bool
	}{
		{
			name: "both resources and test-resources specified",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  resources:
    cpu: "8"
    memory: 16Gi
    disk: 100Gi
  test-resources:
    cpu: "4"
    memory: 8Gi
    disk: 50Gi
`,
			expectResources: &Resources{
				CPU:    "8",
				Memory: "16Gi",
				Disk:   "100Gi",
			},
			expectTestResources: &Resources{
				CPU:    "4",
				Memory: "8Gi",
				Disk:   "50Gi",
			},
			expectParseError: false,
		},
		{
			name: "only test-resources specified",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  test-resources:
    cpu: "4"
    memory: 8Gi
`,
			expectResources: &Resources{
				CPU:    "",
				Memory: "",
			},
			expectTestResources: &Resources{
				CPU:    "4",
				Memory: "8Gi",
			},
			expectParseError: false,
		},
		{
			name: "only resources specified (backward compatible)",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  resources:
    cpu: "4"
    memory: 8Gi
`,
			expectResources: &Resources{
				CPU:    "4",
				Memory: "8Gi",
			},
			expectTestResources: nil,
			expectParseError:    false,
		},
		{
			name: "neither resources nor test-resources specified",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
`,
			expectResources: &Resources{
				CPU:    "",
				Memory: "",
			},
			expectTestResources: nil,
			expectParseError:    false,
		},
		{
			name: "test-resources needs more resources than build",
			yaml: `
package:
  name: ml-pkg
  version: 2.0.0
  epoch: 0
  resources:
    cpu: "2"
    memory: 4Gi
  test-resources:
    cpu: "32"
    memory: 128Gi
    disk: 500Gi
`,
			expectResources: &Resources{
				CPU:    "2",
				Memory: "4Gi",
			},
			expectTestResources: &Resources{
				CPU:    "32",
				Memory: "128Gi",
				Disk:   "500Gi",
			},
			expectParseError: false,
		},
		{
			name: "cpumodel in test-resources",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  test-resources:
    cpu: "4"
    cpumodel: "intel-xeon"
    memory: 8Gi
`,
			expectResources: &Resources{
				CPU:    "",
				Memory: "",
			},
			expectTestResources: &Resources{
				CPU:      "4",
				CPUModel: "intel-xeon",
				Memory:   "8Gi",
			},
			expectParseError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := filepath.Join(t.TempDir(), "melange-test-resources-"+tt.name)
			if err := os.WriteFile(fp, []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}

			cfg, err := ParseConfiguration(ctx, fp)
			if tt.expectParseError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.expectResources != nil {
				require.NotNil(t, cfg.Package.Resources)
				require.Equal(t, tt.expectResources.CPU, cfg.Package.Resources.CPU)
				require.Equal(t, tt.expectResources.Memory, cfg.Package.Resources.Memory)
				require.Equal(t, tt.expectResources.Disk, cfg.Package.Resources.Disk)
				require.Equal(t, tt.expectResources.CPUModel, cfg.Package.Resources.CPUModel)
			} else {
				require.Nil(t, cfg.Package.Resources)
			}

			if tt.expectTestResources != nil {
				require.NotNil(t, cfg.Package.TestResources)
				require.Equal(t, tt.expectTestResources.CPU, cfg.Package.TestResources.CPU)
				require.Equal(t, tt.expectTestResources.Memory, cfg.Package.TestResources.Memory)
				require.Equal(t, tt.expectTestResources.Disk, cfg.Package.TestResources.Disk)
				require.Equal(t, tt.expectTestResources.CPUModel, cfg.Package.TestResources.CPUModel)
			} else {
				require.Nil(t, cfg.Package.TestResources)
			}
		})
	}
}

func TestTestResourcesEdgeCases(t *testing.T) {
	ctx := slogtest.Context(t)

	tests := []struct {
		name             string
		yaml             string
		expectParseError bool
		checkFunc        func(*testing.T, *Configuration)
	}{
		{
			name: "empty test-resources object",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  test-resources: {}
`,
			expectParseError: false,
			checkFunc: func(t *testing.T, cfg *Configuration) {
				require.NotNil(t, cfg.Package.TestResources)
				require.Empty(t, cfg.Package.TestResources.CPU)
				require.Empty(t, cfg.Package.TestResources.Memory)
			},
		},
		{
			name: "malformed yaml - invalid indentation",
			yaml: `
package:
  name: test-pkg
version: 1.0.0
  epoch: 0
`,
			expectParseError: true,
		},
		{
			name: "test-resources with all fields specified",
			yaml: `
package:
  name: test-pkg
  version: 1.0.0
  epoch: 0
  test-resources:
    cpu: "16"
    cpumodel: "intel-xeon-platinum"
    memory: "256Gi"
    disk: "2Ti"
`,
			expectParseError: false,
			checkFunc: func(t *testing.T, cfg *Configuration) {
				require.NotNil(t, cfg.Package.TestResources)
				require.Equal(t, "16", cfg.Package.TestResources.CPU)
				require.Equal(t, "intel-xeon-platinum", cfg.Package.TestResources.CPUModel)
				require.Equal(t, "256Gi", cfg.Package.TestResources.Memory)
				require.Equal(t, "2Ti", cfg.Package.TestResources.Disk)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := filepath.Join(t.TempDir(), "melange-test-resources-edge-"+tt.name)
			if err := os.WriteFile(fp, []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}

			cfg, err := ParseConfiguration(ctx, fp)
			if tt.expectParseError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, cfg)
			}
		})
	}
}
