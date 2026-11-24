package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUpdatePipelineWithGitAm(t *testing.T) {
	const head = "package:\n  name: x\n  version: 1\n  epoch: 0\n\n"

	for _, tt := range []struct {
		name string
		in   string
		want string
	}{{
		name: "patch is replaced in place",
		in: head + `pipeline:
  - uses: git-checkout
  - uses: patch
    with:
      patches: a.patch
  - runs: echo build
`,
		want: head + `pipeline:
  - uses: git-checkout
  - uses: git-am
    with:
      patches: 0001.patch
  - runs: echo build
`,
	}, {
		name: "git-am goes after git-checkout when there is no patch",
		in: head + `pipeline:
  - uses: git-checkout
  - runs: echo build
`,
		want: head + `pipeline:
  - uses: git-checkout
  - uses: git-am
    with:
      patches: 0001.patch
  - runs: echo build
`,
	}, {
		name: "git-checkout and patch in finalize",
		in: head + `pipeline:
  - runs: echo build

finalize:
  - uses: git-checkout
  - uses: patch
    with:
      patches: a.patch
`,
		want: head + `pipeline:
  - runs: echo build

finalize:
  - uses: git-checkout
  - uses: git-am
    with:
      patches: 0001.patch
`,
	}, {
		name: "patch in the other stage is dropped, not applied twice",
		in: head + `pipeline:
  - uses: git-checkout
  - runs: echo build

finalize:
  - uses: patch
    with:
      patches: a.patch
  - runs: echo done
`,
		want: head + `pipeline:
  - uses: git-checkout
  - uses: git-am
    with:
      patches: 0001.patch
  - runs: echo build

finalize:
  - runs: echo done
`,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			var doc, want yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(tt.in), &doc))
			require.NoError(t, yaml.Unmarshal([]byte(tt.want), &want))

			require.NoError(t, updatePipelineWithGitAm(&doc, []string{"0001.patch"}))

			var got, exp any
			require.NoError(t, doc.Decode(&got))
			require.NoError(t, want.Decode(&exp))
			require.Equal(t, exp, got)
		})
	}

	t.Run("no stage is an error", func(t *testing.T) {
		var doc yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte(head), &doc))
		require.Error(t, updatePipelineWithGitAm(&doc, []string{"0001.patch"}))
	})
}
