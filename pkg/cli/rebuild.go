package cli

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container/docker"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// TODO: Detect when the package is a subpackage (origin is different) and compare against the subpackage after building all packages.
// TODO: Avoid rebuilding twice when rebuilding two subpackages of the same origin.
// TODO: Add `--diff` flag to show the differences between the original and rebuilt packages, or document how to do it with shell commands.

func rebuild() *cobra.Command {
	return &cobra.Command{
		Use:               "rebuild",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Rebuild a melange package.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			r, err := docker.NewRunner(ctx)
			if err != nil {
				return fmt.Errorf("failed to create docker runner: %v", err)
			}

			for _, a := range args {
				cfg, pkginfo, err := getConfig(a)
				if err != nil {
					return fmt.Errorf("failed to get config for %s: %v", a, err)
				}

				// TODO: This should not be necessary.
				cfg.Environment.Contents.RuntimeRepositories = append(cfg.Environment.Contents.RuntimeRepositories, "https://packages.wolfi.dev/os")
				cfg.Environment.Contents.Keyring = append(cfg.Environment.Contents.Keyring, "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub")

				f, err := os.CreateTemp("", "melange-rebuild-*.")
				if err != nil {
					return fmt.Errorf("failed to create temporary file: %v", err)
				}
				if err := yaml.NewEncoder(f).Encode(cfg); err != nil {
					return fmt.Errorf("failed to encode stripped config: %v", err)
				}
				log.Println("wrote stripped config to", f.Name())

				if err := BuildCmd(ctx,
					[]apko_types.Architecture{apko_types.Architecture("amd64")},          // TODO configurable, or detect
					build.WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"), // TODO get this from the package SBOM
					build.WithConfigFileRepositoryCommit("TODO"),                         // TODO get this from the package SBOM
					build.WithConfigFileLicense("Apache-2.0"),                            // TODO get this from the package SBOM
					build.WithBuildDate(time.Unix(pkginfo.BuildDate, 0).Format(time.RFC3339)),
					build.WithRunner(r), // TODO configurable
					build.WithConfig(f.Name())); err != nil {
					return fmt.Errorf("failed to rebuild %q: %v", a, err)
				}
			}

			return nil
		},
	}
}

func getConfig(fn string) (*config.Configuration, *goapk.PackageInfo, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %s: %v", fn, err)
	}
	defer f.Close()

	var cfg *config.Configuration
	var pkginfo *goapk.PackageInfo

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if cfg == nil {
				return nil, nil, fmt.Errorf("failed to find .melange.yaml in %s", fn)
			}
			if pkginfo == nil {
				return nil, nil, fmt.Errorf("failed to find .PKGINFO in %s", fn)
			}
			return nil, nil, fmt.Errorf("failed to find necessary rebuild information in %s", fn)
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to read tar header: %v", err)
		}

		switch hdr.Name {
		case ".melange.yaml":
			cfg = new(config.Configuration)
			if err := yaml.NewDecoder(io.LimitReader(tr, hdr.Size)).Decode(cfg); err != nil {
				return nil, nil, fmt.Errorf("failed to decode .melange.yaml: %v", err)
			}

		case ".PKGINFO":
			i, err := ini.ShadowLoad(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to load .PKGINFO: %v", err)
			}
			pkginfo = new(goapk.PackageInfo)
			if err = i.MapTo(pkginfo); err != nil {
				return nil, nil, fmt.Errorf("failed to map .PKGINFO: %v", err)
			}

		default:
			// TODO: Get the SBOM, since we need some info from it too.
			continue
		}

		if cfg != nil && pkginfo != nil {
			return cfg, pkginfo, nil
		}
	}
	// unreachable
}
