package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
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
		// The patch in the other stage may aim at something other than the
		// checkout, and `source get` did not apply it, so pop leaves it alone.
		name: "patch in the other stage is left alone",
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
  - uses: patch
    with:
      patches: a.patch
  - runs: echo done
`,
	}, {
		name: "patch in the checkout's stage is replaced, the other stage's is kept",
		in: head + `pipeline:
  - uses: git-checkout
  - uses: patch
    with:
      patches: a.patch

finalize:
  - uses: patch
    with:
      patches: b.patch
`,
		want: head + `pipeline:
  - uses: git-checkout
  - uses: git-am
    with:
      patches: 0001.patch

finalize:
  - uses: patch
    with:
      patches: b.patch
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

func TestGitCheckoutStage(t *testing.T) {
	checkout := func(repo string) config.Pipeline {
		return config.Pipeline{Uses: "git-checkout", With: map[string]string{"repository": repo}}
	}
	run := config.Pipeline{Runs: "echo"}

	for _, tt := range []struct {
		name      string
		cfg       config.Configuration
		wantRepo  string
		wantIndex int
	}{{
		name:      "main pipeline",
		cfg:       config.Configuration{Pipeline: []config.Pipeline{run, checkout("main")}},
		wantRepo:  "main",
		wantIndex: 1,
	}, {
		name:      "finalize only",
		cfg:       config.Configuration{Pipeline: []config.Pipeline{run}, Finalize: []config.Pipeline{run, checkout("fin")}},
		wantRepo:  "fin",
		wantIndex: 1,
	}, {
		name: "main pipeline wins over finalize",
		cfg: config.Configuration{
			Pipeline: []config.Pipeline{checkout("main")},
			Finalize: []config.Pipeline{checkout("fin")},
		},
		wantRepo:  "main",
		wantIndex: 0,
	}, {
		name:      "none",
		cfg:       config.Configuration{Pipeline: []config.Pipeline{run}, Finalize: []config.Pipeline{run}},
		wantIndex: -1,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			stage, i := gitCheckoutStage(&tt.cfg)
			require.Equal(t, tt.wantIndex, i)
			if i != -1 {
				require.Equal(t, tt.wantRepo, stage[i].With["repository"])
			}
		})
	}
}
