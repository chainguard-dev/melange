package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_applySubstitutionsInProvides(t *testing.T) {
	fp := filepath.Join(os.TempDir(), "melange-test-applySubstitutionsInProvides")
	os.WriteFile(fp, []byte(`
package:
  name: replacement-provides
  version: 0.0.1
  description: example using a replacement in provides
  dependencies:
    provides:
      - replacement-provides-version=${{package.version}}
      - replacement-provides-foo=${{vars.foo}}
      - replacement-provides-bar=${{vars.bar}}

vars:
  foo: FOO
  bar: BAR

subpackages:
  - name: subpackage
    dependencies:
      provides:
        - subpackage-version=${{package.version}}
        - subpackage-foo=${{vars.foo}}
        - subpackage-bar=${{vars.bar}}
`), 0644)
	cfg, err := ParseConfiguration(fp)
	if err != nil {
		t.Fatalf("failed to parse configuration: %s", err)
	}
	require.Equal(t, []string{
		"replacement-provides-version=0.0.1",
		"replacement-provides-foo=FOO",
		"replacement-provides-bar=BAR",
	}, cfg.Package.Dependencies.Provides)

	require.Equal(t, []string{
		"subpackage-version=0.0.1",
		"subpackage-foo=FOO",
		"subpackage-bar=BAR",
	}, cfg.Subpackages[0].Dependencies.Provides)
}
