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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/chainguard-dev/clog"
)

var packageMetadataTemplate = `{"type":"apk","os":"{{.Namespace}}","name":"{{.Configuration.Package.Name}}","version":"{{.Configuration.Package.FullVersion}}","architecture":"{{.Arch.ToAPK}}"{{if .Configuration.Package.CPE.Vendor}},"appCpe":"{{.Configuration.Package.CPEString}}"{{end}}}`

var gccLinkTemplate = `*link:
+ --package-metadata=` + packageMetadataTemplate + `
`

var clangConfigTemplate = `-Xlinker --package-metadata='` + packageMetadataTemplate + `'
`

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

// detectClangSystemConfigDirs returns directories that match /etc/clang-<digits>
func detectClangSystemConfigDirs() ([]string, error) {
	var clangDirs []string

	entries, err := os.ReadDir("/etc")
	if err != nil {
		if os.IsNotExist(err) {
			return clangDirs, nil
		}
		return nil, err
	}

	dirPattern := regexp.MustCompile(`^clang-(\d+)$`)

	for _, entry := range entries {
		if entry.IsDir() && dirPattern.MatchString(entry.Name()) {
			clangDirs = append(clangDirs, filepath.Join("/etc", entry.Name()))
		}
	}

	return clangDirs, nil
}

// detectClangSystemConfigFiles returns files that match
//
//	/etc/clang-<digits>/<arch>-*-clang(++)?.cfg
func (b *Build) detectClangSystemConfigFiles() ([]string, error) {
	configFiles := []string{}

	clangDirs, err := detectClangSystemConfigDirs()
	if err != nil {
		return nil, err
	}

	arch := b.Arch.ToAPK()
	basePattern := regexp.MustCompile(`^` + regexp.QuoteMeta(arch) + `-.*-clang(\+\+)?\.cfg$`)

	for _, dir := range clangDirs {
		dirEntries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range dirEntries {
			fileType := entry.Type()
			if !fileType.IsRegular() && fileType&fs.ModeSymlink == 0 {
				continue
			}

			if !basePattern.MatchString(entry.Name()) {
				continue
			}

			configFiles = append(configFiles, filepath.Join(dir, entry.Name()))
		}
	}

	return configFiles, nil
}

// createClangConfigFile creates a clang config file that includes other config files
func createClangConfigFile(outputPath string, includePaths ...string) error {
	var content strings.Builder
	for _, includePath := range includePaths {
		content.WriteString(fmt.Sprintf("@%s\n", includePath))
	}

	if err := os.WriteFile(outputPath, []byte(content.String()), 0o644); err != nil {
		return err
	}

	return nil
}

func (b *Build) createClangConfigFiles(ctx context.Context) error {
	log := clog.FromContext(ctx)

	systemConfigs, err := b.detectClangSystemConfigFiles()
	if err != nil {
		log.Warnf("failed to detect clang system configs: %v", err)
		return nil
	}

	if len(systemConfigs) == 0 {
		log.Debugf("no clang system config files detected, skipping user config file creation")
		return nil
	}

	// Write the needed config to a single config files that the
	// per-version config files will each include.
	clangConfigFile, err := os.Create(filepath.Join(b.WorkspaceDir, ".melange.clang.cfg"))
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

	configBaseDir := filepath.Join(b.WorkspaceDir, ".config")
	baseConfigPath := filepath.Join(b.WorkspaceDir, ".melange.clang.cfg")

	for _, systemConfigPath := range systemConfigs {
		versionDir := filepath.Base(filepath.Dir(systemConfigPath))
		cfgFilename := filepath.Base(systemConfigPath)

		userConfigDir := filepath.Join(configBaseDir, versionDir)
		if err := os.MkdirAll(userConfigDir, 0o755); err != nil {
			log.Warnf("failed to create clang config directory %s: %v", userConfigDir, err)
			continue
		}

		userConfigPath := filepath.Join(userConfigDir, cfgFilename)
		if err := createClangConfigFile(userConfigPath, baseConfigPath, systemConfigPath); err != nil {
			log.Warnf("failed to write clang driver config %s: %v", userConfigPath, err)
			continue
		}

		log.Debugf("wrote clang driver config to %s", userConfigPath)
	}

	return nil
}

// For now, just the gcc spec file and clang config files with link settings.
// In the future can control debug symbol generation, march/mtune, etc.
func (b *Build) createCompilerConfigFiles(ctx context.Context) error {
	if err := b.createGccSpecFile(); err != nil {
		return err
	}
	if err := b.createClangConfigFiles(ctx); err != nil {
		return err
	}
	return nil
}
