package cli

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// TODO: Detect when the package is a subpackage (origin is different) and compare against the subpackage after building all packages.
// TODO: Avoid rebuilding twice when rebuilding two subpackages of the same origin.
// TODO: Add `--diff` flag to show the differences between the original and rebuilt packages, or document how to do it with shell commands.

func rebuild() *cobra.Command {
	var runner string
	cmd := &cobra.Command{
		Use:               "rebuild",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Rebuild a melange package.",
		Long:              "THIS IS AN EXPERIMENTAL FEATURE",
		Hidden:            true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			r, err := getRunner(ctx, runner, true)
			if err != nil {
				return fmt.Errorf("failed to create runner: %v", err)
			}

			for _, a := range args {
				cfg, pkginfo, cfgpkg, err := getConfig(a)
				if err != nil {
					return fmt.Errorf("failed to get config for %s: %v", a, err)
				}

				// TODO: This should not be necessary.
				cfg.Environment.Contents.RuntimeRepositories = append(cfg.Environment.Contents.RuntimeRepositories, "https://packages.wolfi.dev/os")
				cfg.Environment.Contents.Keyring = append(cfg.Environment.Contents.Keyring, "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub")

				f, err := os.Create(fmt.Sprintf("%s.yaml", cfg.Package.Name))
				if err != nil {
					return fmt.Errorf("failed to create temporary file: %v", err)
				}
				if err := yaml.NewEncoder(f).Encode(cfg); err != nil {
					return fmt.Errorf("failed to encode stripped config: %v", err)
				}
				defer f.Close()
				defer os.Remove(f.Name())

				if err := BuildCmd(ctx,
					[]apko_types.Architecture{apko_types.Architecture("amd64")},          // TODO configurable, or detect
					build.WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"), // TODO get this from the package SBOM
					build.WithNamespace("wolfi"),                                         // TODO get this from the package SBOM
					build.WithConfigFileRepositoryCommit(cfgpkg.Version),
					build.WithConfigFileLicense(cfgpkg.LicenseDeclared),
					build.WithBuildDate(time.Unix(pkginfo.BuildDate, 0).UTC().Format(time.RFC3339)),
					build.WithRunner(r),
					build.WithConfig(f.Name())); err != nil {
					return fmt.Errorf("failed to rebuild %q: %v", a, err)
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	return cmd
}

func getConfig(fn string) (*config.Configuration, *goapk.PackageInfo, *spdx.Package, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open file %s: %v", fn, err)
	}
	defer f.Close()

	var cfg *config.Configuration
	var pkginfo *goapk.PackageInfo
	var cfgpkg *spdx.Package

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if cfg == nil {
				return nil, nil, nil, fmt.Errorf("failed to find .melange.yaml in %s", fn)
			}
			if pkginfo == nil {
				return nil, nil, nil, fmt.Errorf("failed to find .PKGINFO in %s", fn)
			}
			if cfgpkg == nil {
				return nil, nil, nil, fmt.Errorf("failed to find SBOM in %s", fn)
			}
			return nil, nil, nil, fmt.Errorf("failed to find necessary rebuild information in %s", fn)
		} else if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read tar header: %v", err)
		}

		switch hdr.Name {
		case ".melange.yaml":
			cfg = new(config.Configuration)
			if err := yaml.NewDecoder(io.LimitReader(tr, hdr.Size)).Decode(cfg); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decode .melange.yaml: %v", err)
			}

		case ".PKGINFO":
			i, err := ini.ShadowLoad(tr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to load .PKGINFO: %v", err)
			}
			pkginfo = new(goapk.PackageInfo)
			if err = i.MapTo(pkginfo); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to map .PKGINFO: %v", err)
			}

		case fmt.Sprintf("var/lib/db/sbom/%s-%s.spdx.json", pkginfo.Name, pkginfo.Version),
			fmt.Sprintf("var/lib/db/sbom/%s-%s-r%d.spdx.json", cfg.Package.Name, cfg.Package.Version, cfg.Package.Epoch):
			doc := new(spdx.Document)
			if err := json.NewDecoder(io.LimitReader(tr, hdr.Size)).Decode(doc); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decode SBOM: %v", err)
			}

			for _, p := range doc.Packages {
				if strings.HasSuffix(p.Name, ".yaml") {
					cfgpkg = &p
					break
				}
			}
			if cfgpkg == nil {
				return nil, nil, nil, fmt.Errorf("failed to find config package info in SBOM: %v", err)
			}

		default:
			continue
		}

		if cfg != nil && pkginfo != nil && cfgpkg != nil {
			return cfg, pkginfo, cfgpkg, nil
		}
	}
	// unreachable
}
