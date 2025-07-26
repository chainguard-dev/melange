// Copyright 2023 Chainguard, Inc.
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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/melange/internal/sca"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
)

type scanConfig struct {
	key      string
	repo     string
	pkg      string
	archs    []string
	diff     bool
	comments bool

	purlNamespace string
}

func scan() *cobra.Command {
	sc := scanConfig{}

	cmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan an existing APK to regenerate .PKGINFO",
		Example: `melange scan bash.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return scanCmd(cmd.Context(), args[0], &sc)
		},
	}

	// These are oddly named but they match what we do in other tools, which makes this much easier to copy/paste.
	cmd.Flags().StringVarP(&sc.key, "keyring-append", "k", "local-melange.rsa.pub", "path to key to include in the build environment keyring")
	cmd.Flags().StringVarP(&sc.repo, "repository-append", "r", "./packages", "path to repository to include in the build environment")
	cmd.Flags().StringVarP(&sc.pkg, "package", "p", "", "which package's .PKGINFO to print (if there are subpackages)")

	cmd.Flags().StringSliceVar(&sc.archs, "arch", []string{}, "architectures to scan (default is x86_64)")
	cmd.Flags().BoolVar(&sc.diff, "diff", false, "show diff output")
	cmd.Flags().BoolVar(&sc.comments, "comments", false, "include comments in .PKGINFO diff")

	cmd.Flags().StringVar(&sc.purlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")

	return cmd
}

// TODO: It would be cool if there was a way this could take just a directory.
func scanCmd(ctx context.Context, file string, sc *scanConfig) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "scan")
	defer span.End()

	log := clog.FromContext(ctx)

	sawDiff := false

	archs := sc.archs
	if len(archs) == 0 {
		archs = []string{"x86_64"}
	}

	cfg, err := config.ParseConfiguration(ctx, file)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	for _, arch := range archs {
		exps := map[string]*expandapk.APKExpanded{}

		pkg := cfg.Package

		u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", sc.repo, arch, pkg.Name, pkg.Version, pkg.Epoch)

		var r io.Reader
		if strings.HasPrefix(u, "http") {
			resp, err := http.Get(u)
			if err != nil {
				return fmt.Errorf("get %s: %w", u, err)
			}
			r = resp.Body
		} else {
			r, err = os.Open(u)
			if err != nil {
				return err
			}
		}
		exp, err := expandapk.ExpandApk(ctx, r, "")
		if err != nil {
			return err
		}
		defer exp.Close()

		exps[pkg.Name] = exp

		f, err := exp.ControlFS.Open(".PKGINFO")
		if err != nil {
			return fmt.Errorf("opening .PKGINFO in %s: %w", exp.ControlFile, err)
		}
		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		info, err := parsePkgInfo(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("parsing .PKGINFO: %w", err)
		}

		pkg.Commit = info.commit

		installedSize, err := strconv.ParseInt(info.size, 10, 64)
		if err != nil {
			return err
		}

		dir, err := os.MkdirTemp("", info.pkgname)
		if err != nil {
			return fmt.Errorf("mkdirtemp: %w", err)
		}
		defer os.RemoveAll(dir)

		bb := &build.Build{
			WorkspaceDir:    dir,
			SourceDateEpoch: time.Unix(0, 0),
			Configuration:   cfg,
			Namespace:       sc.purlNamespace,
		}

		pb := build.PackageBuild{
			Build:         bb,
			Origin:        &pkg,
			PackageName:   pkg.Name,
			OriginName:    pkg.Name,
			Dependencies:  pkg.Dependencies,
			Options:       pkg.Options,
			Scriptlets:    pkg.Scriptlets,
			Description:   pkg.Description,
			URL:           pkg.URL,
			Commit:        pkg.Commit,
			InstalledSize: installedSize,
			DataHash:      info.datahash,
			Arch:          info.arch,
		}

		if info.builddate != "" {
			sec, err := strconv.ParseInt(info.builddate, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
			}
			pb.Build.SourceDateEpoch = time.Unix(sec, 0)
		}

		subpkgs := map[string]build.PackageBuild{}
		controls := map[string][]byte{}
		infos := map[string]*pkginfo{}

		for _, subpkg := range cfg.Subpackages {
			u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", sc.repo, arch, subpkg.Name, pkg.Version, pkg.Epoch)

			var r io.Reader
			if strings.HasPrefix(u, "http") {
				resp, err := http.Get(u)
				if err != nil {
					return fmt.Errorf("get %s: %w", u, err)
				}
				if resp.StatusCode != http.StatusOK {
					log.Errorf("Get %s: %d", u, resp.StatusCode)
					continue
				}
				r = resp.Body
			} else {
				r, err = os.Open(u)
				if err != nil {
					return err
				}
			}

			exp, err := expandapk.ExpandApk(ctx, r, "")
			if err != nil {
				return err
			}
			defer exp.Close()

			exps[subpkg.Name] = exp

			f, err := exp.ControlFS.Open(".PKGINFO")
			if err != nil {
				return fmt.Errorf("opening .PKGINFO in %s: %w", exp.ControlFile, err)
			}
			defer f.Close()

			b, err := io.ReadAll(f)
			if err != nil {
				return err
			}
			info, err := parsePkgInfo(bytes.NewReader(b))
			if err != nil {
				return fmt.Errorf("parsing .PKGINFO: %w", err)
			}

			infos[subpkg.Name] = info
			controls[subpkg.Name] = b

			subpkg.Commit = info.commit

			installedSize, err := strconv.ParseInt(info.size, 10, 64)
			if err != nil {
				return err
			}

			pb := build.PackageBuild{
				Build:         bb,
				Origin:        &pkg,
				PackageName:   subpkg.Name,
				OriginName:    pkg.Name,
				Dependencies:  subpkg.Dependencies,
				Options:       subpkg.Options,
				Scriptlets:    subpkg.Scriptlets,
				Description:   subpkg.Description,
				URL:           subpkg.URL,
				Commit:        subpkg.Commit,
				InstalledSize: installedSize,
				DataHash:      info.datahash,
				Arch:          info.arch,
			}

			subpkgs[subpkg.Name] = pb

			if info.builddate != "" {
				sec, err := strconv.ParseInt(info.builddate, 10, 64)
				if err != nil {
					return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
				}
				pb.Build.SourceDateEpoch = time.Unix(sec, 0)
			}
		}

		for _, subpkg := range cfg.Subpackages {
			pb, ok := subpkgs[subpkg.Name]
			if !ok {
				continue
			}
			info := infos[subpkg.Name]

			hdl := &scaImpl{
				pb:   &pb,
				exps: exps,
			}

			if err := pb.GenerateDependencies(ctx, hdl); err != nil {
				return err
			}

			var buf bytes.Buffer
			if err := pb.GenerateControlData(&buf); err != nil {
				return fmt.Errorf("unable to process control template: %w", err)
			}

			generated := buf.Bytes()

			if sc.diff {
				b := controls[subpkg.Name]
				old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)

				diff := util.Diff(old, b, file, generated, sc.comments)
				if diff != nil {
					sawDiff = true
					os.Stdout.Write(diff)
				}
			} else if sc.pkg == "" || sc.pkg == subpkg.Name {
				os.Stdout.Write(generated)
			}
		}

		hdl := &scaImpl{
			pb:   &pb,
			exps: exps,
		}

		if err := pb.GenerateDependencies(ctx, hdl); err != nil {
			return err
		}

		var buf bytes.Buffer
		if err := pb.GenerateControlData(&buf); err != nil {
			return fmt.Errorf("unable to process control template: %w", err)
		}

		generated := buf.Bytes()

		if sc.diff {
			old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)
			diff := util.Diff(old, b, file, generated, sc.comments)
			if diff != nil {
				sawDiff = true
				os.Stdout.Write(diff)
			}
		} else if sc.pkg == "" || sc.pkg == pkg.Name {
			os.Stdout.Write(generated)
		}
	}

	if sawDiff {
		return fmt.Errorf("saw diff for %s", file)
	}

	return nil
}

type pkginfo struct {
	pkgname   string
	pkgver    string
	size      string
	arch      string
	origin    string
	pkgdesc   string
	url       string
	commit    string
	builddate string
	license   string
	triggers  string
	datahash  string
}

// TODO: import "gopkg.in/ini.v1"
func parsePkgInfo(in io.Reader) (*pkginfo, error) {
	scanner := bufio.NewScanner(in)

	pkg := pkginfo{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)

		switch before {
		case "pkgname":
			pkg.pkgname = after
		case "pkgver":
			pkg.pkgver = after
		case "arch":
			pkg.arch = after
		case "size":
			pkg.size = after
		case "origin":
			pkg.origin = after
		case "pkgdesc":
			pkg.pkgdesc = after
		case "url":
			pkg.url = after
		case "commit":
			pkg.commit = after
		case "builddate":
			pkg.builddate = after
		case "license":
			pkg.license = after
		case "triggers":
			pkg.triggers = after
		case "datahash":
			pkg.datahash = after
		}
	}

	return &pkg, scanner.Err()
}

// Based on pkg/build/sca_interface but swapping out dirfs for tarfs
type scaImpl struct {
	pb   *build.PackageBuild
	exps map[string]*expandapk.APKExpanded
}

func (s *scaImpl) PackageName() string {
	return s.pb.PackageName
}

func (s *scaImpl) RelativeNames() []string {
	targets := []string{s.pb.Origin.Name}

	for _, target := range s.pb.Build.Configuration.Subpackages {
		targets = append(targets, target.Name)
	}

	return targets
}

func (s *scaImpl) Version() string {
	return fmt.Sprintf("%s-r%d", s.pb.Origin.Version, s.pb.Origin.Epoch)
}

func (s *scaImpl) FilesystemForRelative(pkgName string) (sca.SCAFS, error) {
	exp, ok := s.exps[pkgName]
	if !ok {
		return nil, fmt.Errorf("no package %q", pkgName)
	}

	return exp.TarFS, nil
}

func (s *scaImpl) Filesystem() (sca.SCAFS, error) {
	return s.FilesystemForRelative(s.PackageName())
}

func (s *scaImpl) Options() config.PackageOption {
	if s.pb.Options == nil {
		return config.PackageOption{}
	}
	return *s.pb.Options
}

func (s *scaImpl) BaseDependencies() config.Dependencies {
	return s.pb.Dependencies
}

func (s *scaImpl) InstalledPackages() map[string]string {
	pkgVersionMap := make(map[string]string)

	for _, fullpkg := range s.pb.Build.Configuration.Environment.Contents.Packages {
		pkg, version, _ := strings.Cut(fullpkg, "=")
		pkgVersionMap[pkg] = version
	}

	// We also include the packages being built.
	for _, pkg := range s.RelativeNames() {
		pkgVersionMap[pkg] = s.Version()
	}

	return pkgVersionMap
}

func (s *scaImpl) PkgResolver() *apk.PkgResolver {
	if s.pb.Build == nil || s.pb.Build.PkgResolver == nil {
		return nil
	}
	return s.pb.Build.PkgResolver
}
