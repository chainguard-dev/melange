package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
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
	purl "github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// TODO: Detect when the package is a subpackage (origin is different) and compare against the subpackage after building all packages.
// TODO: Avoid rebuilding twice when rebuilding two subpackages of the same origin.

func rebuild() *cobra.Command {
	var runner, arch string
	var diff bool
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

				if err := BuildCmd(ctx,
					[]apko_types.Architecture{apko_types.ParseArchitecture(arch)},
					build.WithConfigFileRepositoryURL(fmt.Sprintf("https://github.com/%s/%s", cfgpurl.Namespace, cfgpurl.Name)),
					build.WithNamespace(strings.ToLower(strings.TrimPrefix(cfgpkg.Originator, "Organization: "))),
					build.WithConfigFileRepositoryCommit(cfgpkg.Version),
					build.WithConfigFileLicense(cfgpkg.LicenseDeclared),
					build.WithBuildDate(time.Unix(pkginfo.BuildDate, 0).UTC().Format(time.RFC3339)),
					build.WithRunner(r),
					build.WithOutDir("./rebuilt-packages/"), // TODO configurable?
					build.WithConfiguration(cfg, cfgpurl.Subpath)); err != nil {
					return fmt.Errorf("failed to rebuild %q: %v", a, err)
				}

				if diff {
					old := a
					new := fmt.Sprintf("rebuilt-packages/%s/%s-%s-r%d.apk", arch, cfg.Package.Name, cfg.Package.Version, cfg.Package.Epoch)
					if err := diffAPKs(old, new); err != nil {
						return fmt.Errorf("failed to diff APKs %s and %s: %v", old, new, err)
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringVar(&arch, "arch", "x86_64", "architecture to build for") // TODO: determine this from the package
	cmd.Flags().BoolVar(&diff, "diff", true, "show the differences between the original and rebuilt packages; fail if any differences are found")
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

func diffAPKs(old, new string) error {
	oldf, err := os.Open(old)
	if err != nil {
		return fmt.Errorf("failed to open old APK %s: %v", old, err)
	}
	defer oldf.Close()
	oldm, err := filemap(tar.NewReader(oldf))
	if err != nil {
		return fmt.Errorf("failed to create file map for old APK %s: %v", old, err)
	}

	newf, err := os.Open(new)
	if err != nil {
		return fmt.Errorf("failed to open new APK %s: %v", new, err)
	}
	defer newf.Close()
	newm, err := filemap(tar.NewReader(newf))
	if err != nil {
		return fmt.Errorf("failed to create file map for new APK %s: %v", new, err)
	}

	var errs []error
	for k, v := range oldm {
		if n, ok := newm[k]; !ok {
			errs = append(errs, fmt.Errorf("removed: %s", k))
		} else if v != n {
			errs = append(errs, fmt.Errorf("changed: %s; %s -> %s", k, v, n))
		}
	}
	for k := range newm {
		if _, ok := oldm[k]; !ok {
			errs = append(errs, fmt.Errorf("added: %s", k))
		}
	}
	return errors.Join(errs...)
}

func filemap(tr *tar.Reader) (map[string]string, error) {
	m := make(map[string]string)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return m, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %v", err)
		}
		d := sha256.New()
		if _, err := io.Copy(d, tr); err != nil {
			return nil, fmt.Errorf("failed to hash file %s: %v", hdr.Name, err)
		}
		m[hdr.Name] = fmt.Sprintf("%x", d.Sum(nil))
	}
}
