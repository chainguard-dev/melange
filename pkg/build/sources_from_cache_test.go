// Copyright 2026 Chainguard, Inc.
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
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
)

const (
	sourcesFromCacheSum256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// A zero-width character is invisible in a configuration but not to the file
// system, and no file system folds it away either; it is still not the exact
// spelling.
func TestSourceStepIgnoresFormatCharacters(t *testing.T) {
	for _, uses := range []string{"git\u200c-checkout", "\ufeffgit-checkout", "git-checkout\u200b"} {
		require.Equal(t, "git-checkout", sourceStep(uses), "%q", uses)
	}
	require.Empty(t, sourceStep("git-checkouts"))
}

func TestStrictStep(t *testing.T) {
	require.Equal(t, "git-checkout", strictStep([]string{"git-checkout"}, "git-checkout"))
	require.Empty(t, strictStep(nil, "git-checkout"))
	require.Empty(t, strictStep([]string{"git-checkout"}, "fetch"))
}

// sourcesFromCacheConfig has a source step in each place a command runs one:
// the package, a subpackage, the test and a subpackage's test, and one is a
// pipeline that uses another. A compiled configuration's inline script is the
// one to ignore.
func sourcesFromCacheConfig(buildSteps string) string {
	return `
package:
  name: hello
  version: "1.0.0"
  epoch: 0
pipeline:
` + buildSteps + `
subpackages:
  - name: hello-sub
    pipeline:
      - uses: git-checkout
        with:
          repository: https://example.com/x
    test:
      pipeline:
        - uses: git-checkout
          with:
            repository: https://example.com/x
test:
  pipeline:
    - uses: wrap
    - uses: git-checkout
      with:
        repository: https://example.com/x
      pipeline:
        - runs: echo old inline script
`
}

// sourceStepRuns collects the scripts under every source step in ps, and counts
// the steps.
func sourceStepRuns(ps []config.Pipeline) (runs []string, steps int) {
	for _, p := range ps {
		if sourceStep(p.Uses) != "" {
			steps++
			for _, c := range p.Pipeline {
				runs = append(runs, c.Runs)
			}
			continue
		}
		r, n := sourceStepRuns(p.Pipeline)
		runs, steps = append(runs, r...), steps+n
	}
	return runs, steps
}

func TestStrictSourcesFromCacheCompile(t *testing.T) {
	dir := t.TempDir()
	for name, def := range map[string]string{
		"git-checkout": "inputs:\n  repository:\npipeline:\n  - runs: echo pipeline-dir git-checkout\n",
		"fetch":        "inputs:\n  uri:\n  expected-sha256:\npipeline:\n  - runs: echo pipeline-dir fetch\n",
		"wrap":         "pipeline:\n  - uses: git-checkout\n    with:\n      repository: https://example.com/x\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(def), 0o644))
	}
	parse := func(t *testing.T, yaml string) *config.Configuration {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c.yaml")
		require.NoError(t, os.WriteFile(p, []byte(yaml), 0o644))
		cfg, err := config.ParseConfiguration(t.Context(), p)
		require.NoError(t, err)
		return cfg
	}
	forced := func(t *testing.T, ps []config.Pipeline, want int) {
		t.Helper()
		runs, steps := sourceStepRuns(ps)
		require.Equal(t, want, steps)
		require.NotEmpty(t, runs)
		for _, r := range runs {
			require.Contains(t, r, "MELANGE_SOURCE_RESTORE")
			require.NotContains(t, r, "old inline script")
			require.NotContains(t, r, "pipeline-dir")
		}
	}
	buildSteps := `  - uses: wrap
  - uses: git-checkout
    with:
      repository: https://example.com/x
  - uses: git-checkout
    with:
      repository: https://example.com/x
    pipeline:
      - runs: echo old inline script
`

	t.Run("build compile forces every location", func(t *testing.T) {
		cfg := parse(t, sourcesFromCacheConfig(buildSteps))
		b := &Build{Configuration: cfg, PipelineDirs: []string{dir}, StrictSourcesFromCache: strictSourceKinds}
		require.NoError(t, b.Compile(t.Context()))
		forced(t, cfg.Pipeline, 3)
		forced(t, cfg.Subpackages[0].Pipeline, 1)
		forced(t, cfg.Test.Pipeline, 2)
		forced(t, cfg.Subpackages[0].Test.Pipeline, 1)
	})
	t.Run("test compile forces the test pipelines and leaves the build's", func(t *testing.T) {
		cfg := parse(t, sourcesFromCacheConfig("  - uses: wrap\n"))
		tt := &Test{Configuration: *cfg, PipelineDirs: []string{dir}, StrictSourcesFromCache: strictSourceKinds}
		require.NoError(t, tt.Compile(t.Context()))
		forced(t, cfg.Test.Pipeline, 2)
		forced(t, cfg.Subpackages[0].Test.Pipeline, 1)
		runs, _ := sourceStepRuns(cfg.Pipeline)
		require.Contains(t, runs[0], "pipeline-dir", "the build pipelines are not run by a test")
	})
	t.Run("a fetch step keeps the definition it would have without the flag", func(t *testing.T) {
		cfg := parse(t, "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: fetch\n    with:\n      uri: https://example.com/x\n      expected-sha256: "+sourcesFromCacheSum256+"\n")
		require.NoError(t, (&Build{Configuration: cfg, PipelineDirs: []string{dir}, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context()))
		require.Contains(t, cfg.Pipeline[0].Pipeline[0].Runs, "pipeline-dir fetch")
	})
	t.Run("without the flag nothing changes", func(t *testing.T) {
		cfg := parse(t, sourcesFromCacheConfig("  - uses: wrap\n"))
		cfg.Test.Pipeline = cfg.Test.Pipeline[1:] // the compiled git-checkout step, which is not reloaded without the flag
		b := &Build{Configuration: cfg, PipelineDirs: []string{dir}}
		require.NoError(t, b.Compile(t.Context()))
		runs, _ := sourceStepRuns(cfg.Test.Pipeline)
		require.Contains(t, runs[0], "old inline script")
		runs, _ = sourceStepRuns(cfg.Pipeline)
		require.Contains(t, runs[0], "pipeline-dir")
	})
	t.Run("embedded definitions are not served from another compile's cache", func(t *testing.T) {
		step := "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: git-checkout\n    with:\n      repository: https://example.com/x\n"
		base := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(base, "embedded"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(base, "embedded", "git-checkout.yaml"), []byte("inputs:\n  repository:\npipeline:\n  - runs: echo pipeline-dir git-checkout\n"), 0o644))
		t.Chdir(base)
		// the list whose cache key a sentinel directory name could spell
		dirs := []string{"", "embedded"}
		usesCache.Delete(usesKey(dirs, "git-checkout")) // whatever an earlier compile left there
		require.NoError(t, (&Build{Configuration: parse(t, step), PipelineDirs: dirs}).Compile(t.Context()))
		cfg := parse(t, step)
		require.NoError(t, (&Build{Configuration: cfg, PipelineDirs: dirs, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context()))
		forced(t, cfg.Pipeline, 1)
	})
	t.Run("a source step must be spelled exactly", func(t *testing.T) {
		for uses, want := range map[string]string{
			"./git-checkout":      "spell it git-checkout",
			".//git-checkout":     "spell it git-checkout",
			"Git-Checkout":        "spell it git-checkout",
			"GIT-CHECKOUT":        "spell it git-checkout",
			"git\u200c-checkout":  "spell it git-checkout",
			"\ufeffgit-checkout":  "spell it git-checkout",
			"foo/../git-checkout": "'..'",
			"/git-checkout":       "absolute paths",
		} {
			cfg := parse(t, "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: "+uses+"\n    with:\n      repository: https://example.com/x\n")
			err := (&Build{Configuration: cfg, PipelineDirs: []string{dir}, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context())
			require.ErrorContains(t, err, want, uses)
		}
	})
	t.Run("without the flag ./git-checkout compiles", func(t *testing.T) {
		cfg := parse(t, "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: ./git-checkout\n    with:\n      repository: https://example.com/x\n")
		require.NoError(t, (&Build{Configuration: cfg, PipelineDirs: []string{dir}}).Compile(t.Context()))
	})
	t.Run("kinds set on the struct are validated by compile", func(t *testing.T) {
		const step = "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: git-checkout\n    with:\n      repository: https://example.com/x\n"
		err := (&Build{Configuration: parse(t, step), PipelineDirs: []string{dir}, StrictSourcesFromCache: []string{"Git-Checkout"}}).Compile(t.Context())
		require.ErrorContains(t, err, `unknown step kind "Git-Checkout"`)
		err = (&Test{Configuration: *parse(t, step+"test:\n  pipeline:\n    - uses: git-checkout\n      with:\n        repository: https://example.com/x\n"), PipelineDirs: []string{dir}, StrictSourcesFromCache: []string{"Git-Checkout"}}).Compile(t.Context())
		require.ErrorContains(t, err, `unknown step kind "Git-Checkout"`)
	})
	t.Run("a source step with children other than the compiled shape is refused", func(t *testing.T) {
		for name, children := range map[string]string{
			"two steps":      "      - runs: a\n      - runs: b\n",
			"a nested uses":  "      - uses: wrap\n",
			"a nested group": "      - runs: a\n        pipeline:\n          - runs: b\n",
			"no script":      "      - name: only a name\n",
		} {
			cfg := parse(t, "package:\n  name: h\n  version: \"1\"\n  epoch: 0\npipeline:\n  - uses: git-checkout\n    with:\n      repository: https://example.com/x\n    pipeline:\n"+children)
			err := (&Build{Configuration: cfg, PipelineDirs: []string{dir}, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context())
			require.ErrorContains(t, err, "compiled shape", name)
		}
	})
	t.Run("a compiled step with an input the embedded definition lacks says so", func(t *testing.T) {
		cfg := parse(t, `
package:
  name: hello
  version: "1.0.0"
  epoch: 0
pipeline:
  - uses: git-checkout
    with:
      repository: https://example.com/x
      bogus-input: x
    pipeline:
      - runs: echo old inline script
`)
		err := (&Build{Configuration: cfg, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context())
		require.ErrorContains(t, err, `undefined input "bogus-input"`)
		require.ErrorContains(t, err, "compiled by a melange whose git-checkout inputs differ")
	})
	t.Run("a compiled step records the same packages as it does without the flag", func(t *testing.T) {
		const yaml = `
package:
  name: hello
  version: "1.0.0"
  epoch: 0
environment:
  contents:
    packages: [git, jq]
pipeline:
  - uses: git-checkout
    needs:
      packages: [git, jq]
    with:
      repository: https://example.com/x
    pipeline:
      - runs: echo old inline script
  - name: wrapper
    pipeline:
      - uses: git-checkout
        needs:
          packages: [git, jq]
        with:
          repository: https://example.com/x
        pipeline:
          - runs: echo old inline script
`
		plain, strict := parse(t, yaml), parse(t, yaml)
		require.NoError(t, (&Build{Configuration: plain}).Compile(t.Context()))
		require.NoError(t, (&Build{Configuration: strict, StrictSourcesFromCache: strictSourceKinds}).Compile(t.Context()))
		require.Equal(t, plain.Environment.Contents.Packages, strict.Environment.Contents.Packages)
		require.Equal(t, plain.Pipeline[0].Needs, strict.Pipeline[0].Needs)
		require.Equal(t, plain.Pipeline[1].Pipeline[0].Needs, strict.Pipeline[1].Pipeline[0].Needs)
		require.Equal(t, []string{"git", "jq"}, strict.Pipeline[1].Pipeline[0].Needs.Packages)
	})
}

// sourcesFromCacheEnvRunner records the environment each step runs with,
// merged as the runners merge it: the pod's, then the step's.
type sourcesFromCacheEnvRunner struct {
	tarRunner
	steps []map[string]string
}

func (r *sourcesFromCacheEnvRunner) Run(_ context.Context, cfg *container.Config, envOverride map[string]string, _ ...string) error {
	env := maps.Clone(cfg.Environment)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, envOverride)
	r.steps = append(r.steps, env)
	return nil
}

// A step of an enabled kind runs with MELANGE_SOURCE_RESTORE and
// MELANGE_SOURCE_STRICT both "1", and nothing a configuration, an env file, the
// step or a step nested in it sets can change either. Steps of any other kind
// keep the value they would have without the flag and get no
// MELANGE_SOURCE_STRICT.
func TestStrictSourcesFromCacheInjectsPerStepKind(t *testing.T) {
	const steps = `
pipeline:
  - uses: git-checkout
    environment:
      MELANGE_SOURCE_RESTORE: "1"
      MELANGE_SOURCE_STRICT: ""
    pipeline:
      - runs: "true"
        environment:
          MELANGE_SOURCE_RESTORE: ""
          MELANGE_SOURCE_STRICT: "0"
        pipeline:
          - runs: "true"
            environment:
              MELANGE_SOURCE_RESTORE: "1"
  - uses: fetch
    environment:
      MELANGE_SOURCE_RESTORE: "1"
  - runs: "true"
  - uses: fetch
`
	const head = "package:\n  name: hello\n  version: \"1.0.0\"\n  epoch: 0\n"
	const (
		gitStep = iota // the step, then the steps nested in it
		gitNested
		gitGrandchild
		fetchWithEnv
		plain
		fetchBare
	)
	for _, tt := range []struct {
		name, yaml, envFile string
		pod, strict         string // what a step that sets nothing sees without the flag
	}{
		{"configuration environment", head + "environment:\n  environment:\n    MELANGE_SOURCE_RESTORE: \"1\"\n" + steps, "", "1", ""},
		{"env file", head + steps, "MELANGE_SOURCE_RESTORE=1\n", "1", ""},
		{"nothing set", head + steps, "", "", ""},
		// MELANGE_SOURCE_STRICT set by hand reaches every step, flag or not,
		// which is how a script run on its own is made strict.
		{"set by hand", head + "environment:\n  environment:\n    MELANGE_SOURCE_STRICT: \"1\"\n" + steps, "", "", "1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "c.yaml")
			require.NoError(t, os.WriteFile(cfgPath, []byte(tt.yaml), 0o644))
			var envFiles []string
			if tt.envFile != "" {
				envFiles = []string{filepath.Join(dir, "build.env")}
				require.NoError(t, os.WriteFile(envFiles[0], []byte(tt.envFile), 0o644))
			}
			cfg, err := config.ParseConfiguration(t.Context(), cfgPath, config.WithEnvFilesForParsing(envFiles))
			require.NoError(t, err)

			for _, kinds := range [][]string{nil, {"git-checkout"}} {
				for _, mk := range []func(container.Runner) *pipelineRunner{
					func(r container.Runner) *pipelineRunner {
						return (&Build{Runner: r, StrictSourcesFromCache: kinds}).newPipelineRunner(&container.Config{Environment: cfg.Environment.Environment})
					},
					func(r container.Runner) *pipelineRunner {
						return (&Test{Runner: r, StrictSourcesFromCache: kinds}).newPipelineRunner(&container.Config{Environment: cfg.Environment.Environment})
					},
				} {
					r := &sourcesFromCacheEnvRunner{}
					require.NoError(t, mk(r).runPipelines(t.Context(), cfg.Pipeline))
					got, gotStrict := make([]string, 0, len(r.steps)), make([]string, 0, len(r.steps))
					for _, env := range r.steps {
						got = append(got, env[sourceRestoreEnv])
						gotStrict = append(gotStrict, env[sourceStrictEnv])
					}

					want, wantStrict := make([]string, 6), make([]string, 6)
					want[gitStep], want[gitNested], want[gitGrandchild] = "1", "", "1"
					want[fetchWithEnv], want[plain], want[fetchBare] = "1", tt.pod, tt.pod
					wantStrict[gitStep], wantStrict[gitNested], wantStrict[gitGrandchild] = "", "0", "0"
					wantStrict[fetchWithEnv], wantStrict[plain], wantStrict[fetchBare] = tt.strict, tt.strict, tt.strict
					if kinds != nil {
						for _, i := range []int{gitStep, gitNested, gitGrandchild} {
							want[i], wantStrict[i] = "1", "1"
						}
					}
					require.Equal(t, want, got, "kinds %v", kinds)
					require.Equal(t, wantStrict, gotStrict, "kinds %v", kinds)
				}
			}
		})
	}
}
