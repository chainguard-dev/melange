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

package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const BuiltinPipelineDir = "/usr/share/melange/pipelines"

func Build() *cobra.Command {
	var buildDate string
	var workspaceDir string
	var pipelineDir string
	var sourceDir string
	var cacheDir string
	var guestDir string
	var signingKey string
	var generateIndex bool
	var useProot bool
	var emptyWorkspace bool
	var outDir string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string
	var template string
	var dependencyLog string
	var overlayBinSh string
	var breakpointLabel string
	var continueLabel string

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "Build a package from a YAML configuration file",
		Long:    `Build a package from a YAML configuration file.`,
		Example: `  melange build [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := apko_types.ParseArchitectures(archstrs)
			options := []build.Option{
				build.WithBuildDate(buildDate),
				build.WithWorkspaceDir(workspaceDir),
				build.WithPipelineDir(pipelineDir),
				build.WithCacheDir(cacheDir),
				build.WithGuestDir(guestDir),
				build.WithSigningKey(signingKey),
				build.WithGenerateIndex(generateIndex),
				build.WithUseProot(useProot),
				build.WithEmptyWorkspace(emptyWorkspace),
				build.WithOutDir(outDir),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
				build.WithTemplate(template),
				build.WithDependencyLog(dependencyLog),
				build.WithBinShOverlay(overlayBinSh),
				build.WithBreakpointLabel(breakpointLabel),
				build.WithContinueLabel(continueLabel),
			}

			if len(args) > 0 {
				options = append(options, build.WithConfig(args[0]))

				if sourceDir == "" {
					sourceDir = filepath.Dir(args[0])
				}
			}

			if sourceDir != "" {
				options = append(options, build.WithSourceDir(sourceDir))
			}

			return BuildCmd(cmd.Context(), archs, options...)
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&workspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory used for included sources")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "/var/cache/melange", "directory used for cached inputs")
	cmd.Flags().StringVar(&guestDir, "guest-dir", "", "directory used for the build environment guest")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().BoolVar(&generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().BoolVar(&useProot, "use-proot", false, "whether to use proot for fakeroot")
	cmd.Flags().BoolVar(&emptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	cmd.Flags().StringVar(&outDir, "out-dir", filepath.Join(cwd, "packages"), "directory where packages will be output")
	cmd.Flags().StringVar(&template, "template", "", "template to apply to melange config (optional)")
	cmd.Flags().StringVar(&dependencyLog, "dependency-log", "", "log dependencies to a specified file")
	cmd.Flags().StringVar(&overlayBinSh, "overlay-binsh", "", "use specified file as /bin/sh overlay in build environment")
	cmd.Flags().StringVar(&breakpointLabel, "breakpoint-label", "", "stop build execution at the specified label")
	cmd.Flags().StringVar(&continueLabel, "continue-label", "", "continue build execution at the specified label")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")

	return cmd
}

func BuildCmd(ctx context.Context, archs []apko_types.Architecture, base_opts ...build.Option) error {
	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}

	log.Printf("building for %v", archs)

	var errg errgroup.Group

	// Set up the build contexts before running them.  This avoids various
	// race conditions and the possibility that a context may be garbage
	// collected before it is actually run.
	//
	// Yes, this happens.  Really.
	// https://github.com/distroless/nginx/runs/7219233843?check_suite_focus=true
	bcs := []*build.Context{}
	for _, arch := range archs {
		opts := append(base_opts, build.WithArch(arch), build.WithBuiltinPipelineDirectory(BuiltinPipelineDir))

		bc, err := build.New(opts...)
		if err != nil {
			return err
		}

		bcs = append(bcs, bc)
	}

	for _, bc := range bcs {
		bc := bc

		errg.Go(func() error {
			if err := bc.BuildPackage(); err != nil {
				log.Printf("ERROR: failed to build package. the build environment has been preserved:")
				bc.SummarizePaths()

				return fmt.Errorf("failed to build package: %w", err)
			}

			return nil
		})
	}

	if err := errg.Wait(); err != nil {
		return err
	}

	return nil
}
