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

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"

	"chainguard.dev/melange/pkg/container"
)

func initramfsCmd() *cobra.Command {
	var (
		outputPath   string
		archStr      string
		initPackage  string
		repositories []string
		packages     []string
		extraKeys    []string
	)

	cmd := &cobra.Command{
		Use:   "initramfs",
		Short: "Build a base initramfs for the QEMU runner",
		Long: `Build a base initramfs that can be used with the QEMU runner.

The generated initramfs can be reused across multiple builds by setting
the QEMU_BASE_INITRAMFS environment variable to point to the output file.

The generated initramfs does NOT contain SSH host keys.
Keys and modules are injected at runtime for each build.`,
		Example: `  # Generate default initramfs for x86_64
  melange initramfs --arch x86_64 --output ./initramfs.cpio

  # Generate with custom package and repos
  melange initramfs \
    --arch aarch64 \
    --output ./custom-initramfs.cpio \
    --init-package my-custom-init \
    --repository https://my.repo.dev/packages

  # Use the generated initramfs in a build
  QEMU_BASE_INITRAMFS=./initramfs.cpio melange build --runner qemu ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildInitramfs(cmd.Context(), outputPath, archStr, initPackage, repositories, packages, extraKeys)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "output path for the initramfs (required)")
	cmd.Flags().StringVar(&archStr, "arch", "", "target architecture (e.g., x86_64, aarch64)")
	cmd.Flags().StringVar(&initPackage, "init-package", "microvm-init", "init package to use")
	cmd.Flags().StringSliceVarP(&repositories, "repository", "r", []string{"https://apk.cgr.dev/chainguard"}, "APK repositories to use")
	cmd.Flags().StringSliceVarP(&packages, "package", "p", []string{}, "additional packages to include")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring", "k", []string{}, "extra keys for APK signature verification")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

// BuildInitramfs generates a base initramfs for the QEMU runner.
func BuildInitramfs(ctx context.Context, outputPath, archStr, initPackage string, repositories, packages, extraKeys []string) error {
	log := clog.FromContext(ctx)

	// Determine architecture
	archs := apko_types.ParseArchitectures([]string{archStr})
	if len(archs) == 0 || archStr == "" {
		return fmt.Errorf("--arch is required (e.g., x86_64, aarch64)")
	}
	arch := archs[0]

	cfg := container.MicrovmConfig{
		Package:            initPackage,
		Repositories:       repositories,
		AdditionalPackages: packages,
		ExtraKeys:          extraKeys,
	}

	log.Infof("Generating base initramfs for %s", arch)
	log.Infof("  Init package: %s", cfg.Package)
	log.Infof("  Repositories: %v", cfg.Repositories)
	if len(cfg.AdditionalPackages) > 0 {
		log.Infof("  Additional packages: %v", cfg.AdditionalPackages)
	}
	if len(cfg.ExtraKeys) > 0 {
		log.Infof("  Extra keys: %v", cfg.ExtraKeys)
	}

	if err := container.GenerateBaseInitramfs(ctx, arch, cfg, outputPath); err != nil {
		return fmt.Errorf("failed to generate initramfs: %w", err)
	}

	log.Infof("Successfully wrote initramfs to %s", outputPath)
	log.Infof("To use this initramfs in builds, set: QEMU_BASE_INITRAMFS=%s", outputPath)

	return nil
}
