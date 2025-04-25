package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
	"github.com/chainguard-dev/clog"
	"github.com/google/go-cmp/cmp"
	purl "github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

func rebuild() *cobra.Command {
	var runner, outDir, sourceDir, signingKey string
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

			origins := make(map[string]bool)

			for _, a := range args {
				cfg, pkginfo, cfgpkg, err := getConfig(a)
				if err != nil {
					return fmt.Errorf("failed to get config for %s: %v", a, err)
				}

				cfgpurl, err := purl.FromString(cfgpkg.ExternalRefs[0].Locator)
				if err != nil {
					return fmt.Errorf("failed to parse package URL %q: %v", cfgpkg.ExternalRefs[0].Locator, err)
				}

				arch := pkginfo.Arch

				if origins[pkginfo.Origin] {
					clog.Warnf("not rebuilding %q because was already rebuilt", a)
				} else {
					clog.Infof("rebuilding %q", a)
					opts := []build.Option{
						build.WithConfigFileRepositoryURL(fmt.Sprintf("https://github.com/%s/%s", cfgpurl.Namespace, cfgpurl.Name)),
						build.WithNamespace(strings.ToLower(strings.TrimPrefix(cfgpkg.Originator, "Organization: "))),
						build.WithConfigFileRepositoryCommit(cfgpkg.Version),
						build.WithConfigFileLicense(cfgpkg.LicenseDeclared),
						build.WithBuildDate(time.Unix(pkginfo.BuildDate, 0).UTC().Format(time.RFC3339)),
						build.WithRunner(r),
						build.WithOutDir(outDir),
						build.WithConfiguration(cfg, cfgpurl.Subpath),
						build.WithSigningKey(signingKey),
					}
					if sourceDir != "" {
						opts = append(opts, build.WithSourceDir(sourceDir))
					}

					if err := BuildCmd(ctx,
						[]apko_types.Architecture{apko_types.ParseArchitecture(arch)},
						opts...); err != nil {
						return fmt.Errorf("failed to rebuild %q: %v", a, err)
					}

					origins[pkginfo.Origin] = true
				}

				if diff {
					old := a
					new := filepath.Join(outDir, arch, fmt.Sprintf("%s-%s.apk", pkginfo.Name, pkginfo.Version))
					clog.Infof("diffing %s and %s", old, new)
					if err := diffAPKs(old, new); err != nil {
						return fmt.Errorf("failed to diff APKs %s and %s: %v", old, new, err)
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().BoolVar(&diff, "diff", true, "fail and show differences between the original and rebuilt packages")
	cmd.Flags().StringVar(&outDir, "out-dir", "./rebuilt-packages/", "directory where packages will be output")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory where source code is located")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "path to the signing key to use for signing the rebuilt packages")
	return cmd
}

func getConfig(fn string) (*config.Configuration, *goapk.PackageInfo, *spdx.Package, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open file %s: %v", fn, err)
	}
	defer f.Close()

	cfg := &config.Configuration{}
	pkginfo := &goapk.PackageInfo{}
	cfgpkg := &spdx.Package{}

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if cfg.Package.Name == "" {
				return nil, nil, nil, fmt.Errorf("failed to find .melange.yaml in %s", fn)
			}
			if pkginfo.Name == "" {
				return nil, nil, nil, fmt.Errorf("failed to find .PKGINFO in %s", fn)
			}
			if len(cfgpkg.ExternalRefs) == 0 {
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

		default:
			continue
		}

		if cfg.Package.Name != "" && pkginfo.Name != "" && len(cfgpkg.ExternalRefs) > 0 {
			return cfg, pkginfo, cfgpkg, nil
		}
	}
	// unreachable
}

func diffAPKs(old, new string) error {
	oldh, newh := sha256.New(), sha256.New()
	oldf, err := os.Open(old)
	if err != nil {
		return fmt.Errorf("failed to open old APK %s: %v", old, err)
	}
	defer oldf.Close()
	oldgr, err := gzip.NewReader(io.TeeReader(oldf, oldh))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader for old APK %s: %v", old, err)
	}
	defer oldgr.Close()
	oldm, err := filemap(tar.NewReader(oldgr))
	if err != nil {
		return fmt.Errorf("failed to create file map for old APK %s: %v", old, err)
	}

	newf, err := os.Open(new)
	if err != nil {
		return fmt.Errorf("failed to open new APK %s: %v", new, err)
	}
	defer newf.Close()
	newgr, err := gzip.NewReader(io.TeeReader(newf, newh))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader for old APK %s: %v", old, err)
	}
	defer oldgr.Close()
	newm, err := filemap(tar.NewReader(newgr))
	if err != nil {
		return fmt.Errorf("failed to create file map for new APK %s: %v", new, err)
	}

	var errs []error
	for k, o := range oldm {
		if n, ok := newm[k]; !ok {
			errs = append(errs, fmt.Errorf("removed: %s", k))
		} else if o != n {
			errs = append(errs, fmt.Errorf("changed: %s: digests %s -> %s", k, o.digest, n.digest))
			if o.contents != n.contents {
				errs = append(errs, fmt.Errorf("contents diff: %s (-old,new):\n%s", k, cmp.Diff(o.contents, n.contents)))
			}
		}
	}
	for k := range newm {
		if _, ok := oldm[k]; !ok {
			errs = append(errs, fmt.Errorf("added: %s", k))
		}
	}

	oldd, newd := fmt.Sprintf("%x", oldh.Sum(nil)), fmt.Sprintf("%x", newh.Sum(nil))
	if oldd != newd {
		errs = append(errs, fmt.Errorf("APK digest diff: %s -> %s", oldd, newd))
	}

	return errors.Join(errs...)
}

type entry struct{ digest, contents string }

// Some files should especially not have diffs, and so we want to surface those changes even more prominently.
// Other paths which may have a diff will just be shown as digest changes, and users should inspect those diffs manually.
func isImportantPath(path string) bool {
	switch path {
	case ".PKGINFO", ".melange.yaml":
		return true
	}
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}

func filemap(tr *tar.Reader) (map[string]entry, error) {
	m := make(map[string]entry)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return m, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %v", err)
		}
		h := sha256.New()
		var w io.Writer = h
		var buf bytes.Buffer
		if isImportantPath(hdr.Name) {
			w = io.MultiWriter(w, &buf)
		}
		if _, err := io.Copy(w, tr); err != nil {
			return nil, fmt.Errorf("failed to read tar entry %s: %v", hdr.Name, err)
		}
		entry := entry{digest: fmt.Sprintf("%x", h.Sum(nil))}
		if isImportantPath(hdr.Name) {
			entry.contents = buf.String()
		}
		m[hdr.Name] = entry
	}
}
