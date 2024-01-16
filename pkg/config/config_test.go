package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_applySubstitutionsInProvides(t *testing.T) {
	ctx := context.Background()

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

subpackages:
  - name: subpackage
    dependencies:
      runtime:
        - ${{package.name}}-config-${{package.version}}
        - ${{vars.foo}}
        - other-package=${{package.version}}
      provides:
        - subpackage-version=${{package.version}}
        - subpackage-foo=${{vars.foo}}
        - subpackage-bar=${{vars.bar}}
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
	}, cfg.Subpackages[0].Dependencies.Runtime)

	require.Equal(t, []string{
		"dep~0.0.1",
	}, cfg.Environment.Contents.Packages)
}

func Test_rangeSubstitutions(t *testing.T) {
	ctx := context.Background()

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
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfiguration(ctx, fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}
	require.Equal(t, cfg.Subpackages[0].Dependencies.Runtime[0], "wow-some-kinda-dynamically-linked-library-i-guess=1.0")
	require.True(t, cfg.Subpackages[0].Options.NoProvides)
}

func Test_propagatePipelines(t *testing.T) {
	ctx := context.Background()

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
	ctx := context.Background()
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
	ctx := context.Background()
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
              uri: https://example.com/foo.zip
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
}
