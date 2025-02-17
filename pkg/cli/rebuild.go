package cli

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	purl "github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// TODO: Detect when the package is a subpackage (origin is different) and compare against the subpackage after building all packages.
// TODO: Avoid rebuilding twice when rebuilding two subpackages of the same origin.
// TODO: Add `--diff` flag to show the differences between the original and rebuilt packages, or document how to do it with shell commands.

func rebuild() *cobra.Command {
	var runner string
	var archstrs []string // TODO: Detect this from the APK somehow?
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

				cfgpurl, err := purl.FromString(cfgpkg.ExternalRefs[0].Locator)
				if err != nil {
					return fmt.Errorf("failed to parse package URL %q: %v", cfgpkg.ExternalRefs[0].Locator, err)
				}

				// The name of this file gets included in the SBOM, so it must match the original file name.
				// TODO: Get this path from the SBOM.
				if err := os.MkdirAll(filepath.Dir(cfgpurl.Subpath), 0755); err != nil {
					return fmt.Errorf("failed to create directory for temporary file: %v", err)
				}
				f, err := os.Create(cfgpurl.Subpath)
				if err != nil {
					return fmt.Errorf("failed to create temporary file: %v", err)
				}
				if err := yaml.NewEncoder(f).Encode(cfg); err != nil {
					return fmt.Errorf("failed to encode stripped config: %v", err)
				}
				defer f.Close()
				defer os.Remove(f.Name()) // TODO: THIS IS DESTRUCTIVE!! We need to make a copy and not have that mess up the path we embed into the SBOM's Purls.

				if err := BuildCmd(ctx,
					apko_types.ParseArchitectures(archstrs),
					build.WithConfigFileRepositoryURL(fmt.Sprintf("https://github.com/%s/%s", cfgpurl.Namespace, cfgpurl.Name)),
					build.WithNamespace(strings.ToLower(strings.TrimPrefix(cfgpkg.Originator, "Organization: "))),
					build.WithConfigFileRepositoryCommit(cfgpkg.Version),
					build.WithConfigFileLicense(cfgpkg.LicenseDeclared),
					build.WithBuildDate(time.Unix(pkginfo.BuildDate, 0).UTC().Format(time.RFC3339)),
					build.WithRunner(r),
					build.WithOutDir("./packages/"), // TODO configurable?
					build.WithConfig(f.Name())); err != nil {
					return fmt.Errorf("failed to rebuild %q: %v", a, err)
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
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
				}
			}
			if cfgpkg == nil {
				return nil, nil, nil, errors.New("failed to find config package info in SBOM")
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
