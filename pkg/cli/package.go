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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/apk/tarball"
	"github.com/chainguard-dev/clog"
	"github.com/psanford/memfs"
	"github.com/spf13/cobra"
)

func Package() *cobra.Command {
	var name, version, epoch, description, license, url, commit, outdir string
	var archs, deps, provides, replaces []string
	var providerPriority, replacesPriority int
	cmd := &cobra.Command{
		Use:     "package",
		Short:   "Emit a package for the given directory, tarball or file.",
		Example: `melange package <dir>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)
			fs := fs.DirFS(args[0])

			builddate := time.Now() // TODO: This should be configurable.

			// Data section.
			// Write and buffer this once first, so we can calculate the hash.
			// The data hash will be the same for all archs.
			var databuf bytes.Buffer
			var datahash string
			{
				tc, err := tarball.NewContext(
					tarball.WithUseChecksums(true),
					tarball.WithSourceDateEpoch(builddate),
				)
				if err != nil {
					return fmt.Errorf("failed to create tarball context: %w", err)
				}

				digest := sha256.New()
				mw := io.MultiWriter(&databuf, digest)
				if err := tc.WriteTar(ctx, mw, fs, fs); err != nil {
					return fmt.Errorf("failed to write data section: %w", err)
				}
				datahash = hex.EncodeToString(digest.Sum(nil))
				log.Infof("Data hash: %s", datahash)
			}

			for _, arch := range archs {
				log := clog.FromContext(ctx).With("arch", arch)

				out := filepath.Join(outdir, arch, fmt.Sprintf("%s-%s-r%s.apk", name, version, epoch))

				if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
					return fmt.Errorf("failed to create output directory: %w", err)
				}

				log.Infof("Creating package %s", out)
				f, err := os.Create(out)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()

				// Control section.
				{
					fs := memfs.New()
					var ctrlbuf bytes.Buffer
					if err := template.Must(template.New("control").Parse(controlTemplate)).Execute(&ctrlbuf, controlSection{
						PackageName:      name,
						OriginName:       name, // TODO: This should be configurable.
						Version:          version,
						Epoch:            epoch,
						Description:      description,
						InstalledSize:    databuf.Len(),
						License:          license,
						Arch:             arch,
						BuildDate:        builddate,
						DataHash:         datahash,
						Dependencies:     deps,
						Provides:         provides,
						Replaces:         replaces,
						ProviderPriority: providerPriority,
						ReplacesPriority: replacesPriority,
					}); err != nil {
						return fmt.Errorf("failed to execute control template: %w", err)
					}

					if err := fs.WriteFile(".PKGINFO", ctrlbuf.Bytes(), 0666); err != nil {
						return fmt.Errorf("failed to write .PKGINFO: %w", err)
					}
					tc, err := tarball.NewContext(tarball.WithSkipClose(true))
					if err != nil {
						return fmt.Errorf("failed to create tarball context: %w", err)
					}
					if err := tc.WriteTar(ctx, f, fs, fs); err != nil {
						return fmt.Errorf("failed to write control section: %w", err)
					}
				}

				// Write the buffered data section.
				if _, err := io.Copy(f, bytes.NewReader(databuf.Bytes())); err != nil {
					return fmt.Errorf("failed to write data section: %w", err)
				}
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&name, "name", "", "package name")
	cmd.PersistentFlags().StringVar(&version, "version", "", "package version")
	cmd.PersistentFlags().StringVar(&epoch, "epoch", "0", "package epoch")
	cmd.PersistentFlags().StringVar(&description, "description", "", "package description")
	cmd.PersistentFlags().StringVar(&license, "license", "PROPRIETARY", "package license")
	cmd.PersistentFlags().StringVar(&url, "url", "", "package URL")
	cmd.PersistentFlags().StringVar(&commit, "commit", "", "package commit")
	cmd.PersistentFlags().StringVarP(&outdir, "out-dir", "o", "packages", "output directory")
	cmd.PersistentFlags().StringSliceVar(&deps, "dep", nil, "runtime dependencies")
	cmd.PersistentFlags().StringSliceVar(&provides, "provides", nil, "provides")
	cmd.PersistentFlags().StringSliceVar(&replaces, "replaces", nil, "replaces")
	cmd.PersistentFlags().IntVar(&providerPriority, "provider-priority", 0, "provider priority")
	cmd.PersistentFlags().IntVar(&replacesPriority, "replaces-priority", 0, "replaces priority")
	cmd.PersistentFlags().StringSliceVar(&archs, "arch", []string{"x86_64"}, "package architectures")
	return cmd
}

type controlSection struct {
	PackageName      string
	Version          string
	Epoch            string
	Description      string
	InstalledSize    int
	OriginName       string
	URL              string
	Commit           string
	License          string
	Arch             string
	BuildDate        time.Time
	Dependencies     []string
	Provides         []string
	Replaces         []string
	ProviderPriority int
	ReplacesPriority int
	DataHash         string
}

// This is copied from package.go, should this be shared?
var controlTemplate = `# Generated by melange
pkgname = {{.PackageName}}
pkgver = {{.Version}}-r{{.Epoch}}
arch = {{.Arch}}
size = {{.InstalledSize}}
origin = {{.OriginName}}
pkgdesc = {{.Description}}
url = {{.URL}}
commit = {{.Commit}}
license = {{ .License }}
builddate = {{ .BuildDate.Unix }}
{{- range $dep := .Dependencies }}
depend = {{ $dep }}
{{- end }}
{{- range $dep := .Provides }}
provides = {{ $dep }}
{{- end }}
{{- range $dep := .Replaces }}
replaces = {{ $dep }}
{{- end }}
{{- if .ProviderPriority }}
provider_priority = {{ .ProviderPriority }}
{{- end }}
{{- if .ReplacesPriority }}
replaces_priority = {{ .ReplacesPriority }}
{{- end }}
datahash = {{.DataHash}}
`
