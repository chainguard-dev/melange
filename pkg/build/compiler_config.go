// Copyright 2025-2026 Chainguard, Inc.
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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/chainguard-dev/clog"
)

var packageMetadataTemplate = `{"type":"apk","os":"{{.Namespace}}","name":"{{.Configuration.Package.Name}}","version":"{{.Configuration.Package.FullVersion}}","architecture":"{{.Arch.ToAPK}}"{{if .Configuration.Package.CPE.Vendor}},"appCpe":"{{.Configuration.Package.CPEString}}"{{end}}}`

var gccLinkTemplate = `*link:
+ %{!r:--package-metadata=` + packageMetadataTemplate + `}
`

var clangConfigTemplate = `-Xlinker --package-metadata='` + packageMetadataTemplate + `'
`

// fdoNoteTemplate is a C header, generated alongside the gcc spec file, that
// projects can #include to embed the very same FDO packaging metadata that the
// --package-metadata linker flag would emit. This is useful for statically
// linked or vendored code (e.g. a bundled allocator), which leaves no trace in
// the dynamic dependency graph and is therefore invisible to SBOM / CVE
// scanners: the note travels with the object into the final binary regardless.
//
// The note layout (NT_FDO_PACKAGING_METADATA, owner "FDO") follows
// https://systemd.io/COREDUMP_PACKAGE_METADATA/ . The %s is the C-string-escaped
// metadata JSON, identical to what the linker flag carries.
var fdoNoteTemplate = `#ifndef MELANGE_PACKAGE_NOTE_H
#define MELANGE_PACKAGE_NOTE_H
#if defined(__ELF__)
#define MELANGE_PACKAGE_NOTE_JSON "%s"
__attribute__((used, retain, section(".note.package"), aligned(4)))
static const struct {
	unsigned int namesz;
	unsigned int descsz;
	unsigned int type;
	char name[4];
	char desc[sizeof(MELANGE_PACKAGE_NOTE_JSON)];
} melange_package_note = {
	sizeof("FDO"),
	sizeof(MELANGE_PACKAGE_NOTE_JSON),
	0xcafe1a7e,
	"FDO",
	MELANGE_PACKAGE_NOTE_JSON
};
#endif
#endif
`

// range of clang versions we may support in the foreseeable future
var (
	minClangVer  = 15
	maxClangVer  = 42
	clangArchs   = []string{"aarch64", "x86_64"}
	clangDrivers = []string{"clang", "clang++"}
)

// createGccSpecFile creates the GCC spec file with linker settings
func (b *Build) createGccSpecFile() error {
	specFile, err := os.Create(filepath.Join(b.WorkspaceDir, ".melange.gcc.spec"))
	if err != nil {
		return err
	}
	specTemplate := template.New("gccSpecFile")
	if err := template.Must(specTemplate.Parse(gccLinkTemplate)).Execute(specFile, b); err != nil {
		return err
	}
	if err := specFile.Close(); err != nil {
		return err
	}
	return nil
}

// renderPackageMetadata renders the package metadata JSON (the same payload
// carried by the --package-metadata linker flag) for this build.
func (b *Build) renderPackageMetadata() (string, error) {
	var sb strings.Builder
	tmpl := template.Must(template.New("packageMetadata").Parse(packageMetadataTemplate))
	if err := tmpl.Execute(&sb, b); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// createFdoNoteHeader writes a C header next to the gcc spec file that projects
// can #include to embed the FDO packaging metadata note themselves. See
// fdoNoteTemplate for why this is useful for statically linked / vendored code.
func (b *Build) createFdoNoteHeader() error {
	metadata, err := b.renderPackageMetadata()
	if err != nil {
		return err
	}

	// Escape for embedding in a C string literal: backslash first so we don't
	// double-escape the backslashes we introduce for the quotes.
	escaped := strings.ReplaceAll(metadata, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)

	content := fmt.Sprintf(fdoNoteTemplate, escaped)

	// #nosec G306 -- header should be world-readable so builds can include it
	return os.WriteFile(filepath.Join(b.WorkspaceDir, ".melange.fdo.h"), []byte(content), 0o644)
}

// create a clang config file that just includes other clang config files
func createClangConfigFile(outputPath string, includePaths ...string) error {
	var content strings.Builder
	for _, includePath := range includePaths {
		fmt.Fprintf(&content, "@%s\n", includePath)
	}

	// #nosec G306 -- clang config files should be world-readable
	if err := os.WriteFile(outputPath, []byte(content.String()), 0o644); err != nil {
		return err
	}

	return nil
}

// create all of the possible clang config files that we might need
func (b *Build) createClangConfigFiles(ctx context.Context) error {
	log := clog.FromContext(ctx)
	melangeClangCfg := ".melange.clang.cfg"

	// Write the needed config to a single config file that the
	// per-version config files will each include.
	clangConfigFile, err := os.Create(filepath.Join(b.WorkspaceDir, melangeClangCfg))
	if err != nil {
		return err
	}
	clangTemplate := template.New("clangConfigFile")
	if err := template.Must(clangTemplate.Parse(clangConfigTemplate)).Execute(clangConfigFile, b); err != nil {
		return err
	}
	if err := clangConfigFile.Close(); err != nil {
		return err
	}

	userCfgBaseDir := filepath.Join(b.WorkspaceDir, ".config")
	systemCfgBaseDir := "/etc"
	commonCfgFile := filepath.Join("../../", melangeClangCfg)
	// We don't yet know what clang versions will get installed, so
	// install configs for a range of possible versions. Each includes
	// the common config we wrote out above, followed by the system
	// config file we're overriding. Note: this will cause clang
	// to error if the system config does not exist.
	for clangVer := minClangVer; clangVer < maxClangVer+1; clangVer++ {
		clangSubDir := fmt.Sprintf("clang-%d", clangVer)
		userCfgDir := filepath.Join(userCfgBaseDir, clangSubDir)
		systemCfgDir := filepath.Join(systemCfgBaseDir, clangSubDir)
		if err := os.MkdirAll(userCfgDir, 0o755); err != nil {
			log.Warnf("failed to create clang config directory %s: %v", userCfgDir, err)
			continue
		}
		for _, driver := range clangDrivers {
			for _, arch := range clangArchs {
				cfgFilename := fmt.Sprintf("%s-unknown-linux-gnu-%s.cfg", arch, driver)
				userCfgPath := filepath.Join(userCfgDir, cfgFilename)
				systemCfgPath := filepath.Join(systemCfgDir, cfgFilename)
				if err := createClangConfigFile(userCfgPath, commonCfgFile, systemCfgPath); err != nil {
					log.Warnf("failed to write clang driver config %s: %v", userCfgPath, err)
					continue
				}
				log.Debugf("wrote clang driver config to %s", userCfgPath)
			}
		}
	}
	return nil
}

// For now, just the gcc spec file and clang config files with link settings.
// In the future can control debug symbol generation, march/mtune, etc.
func (b *Build) createCompilerConfigFiles(ctx context.Context) error {
	if err := b.createGccSpecFile(); err != nil {
		return err
	}
	if err := b.createFdoNoteHeader(); err != nil {
		return err
	}
	if err := b.createClangConfigFiles(ctx); err != nil {
		return err
	}
	return nil
}
