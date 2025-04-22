package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
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
`), 0644); err != nil {
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
`), 0644); err != nil {
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
`), 0644); err != nil {
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
`), 0644); err != nil {
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
`), 0644); err != nil {
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
`), 0644); err != nil {
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

`), 0644); err != nil {
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
`), 0644); err != nil {
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
