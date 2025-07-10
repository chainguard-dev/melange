package configlint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
)

const yamlExtension = ".yaml"

// Packages represents a Melange package configuration loaded from disk.
type Packages struct {
	Config   config.Configuration
	Filename string
	Dir      string
	NoLint   []string
	Hash     string
}

type configCheck struct {
	Package struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"package"`
}

func (c configCheck) isMelangeConfig() bool {
	if c.Package.Name == "" {
		return false
	}
	if c.Package.Version == "" {
		return false
	}
	return true
}

// findNoLint reads the given file and returns any #nolint directives.
func findNoLint(filename string) ([]string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#nolint:") {
			return strings.Split(strings.TrimPrefix(line, "#nolint:"), ","), nil
		}
	}
	return nil, nil
}

// ReadAllPackagesFromRepo walks the provided directory and returns all Melange
// package configurations it finds keyed by package name.
func ReadAllPackagesFromRepo(ctx context.Context, dir string) (map[string]*Packages, error) {
	p := make(map[string]*Packages)

	var fileList []string
	err := filepath.WalkDir(dir, func(path string, fi os.DirEntry, _ error) error {
		if fi == nil {
			return fmt.Errorf("%s does not exist", dir)
		}
		if fi.IsDir() && path != dir {
			return filepath.SkipDir
		}
		if filepath.Ext(path) == yamlExtension {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return p, fmt.Errorf("failed walking files in cloned directory %s: %w", dir, err)
	}

	sort.Strings(fileList)

	for _, fi := range fileList {
		data, err := os.ReadFile(fi)
		if err != nil {
			return p, fmt.Errorf("failed to read file %s: %w", fi, err)
		}
		check := &configCheck{}
		if err := yaml.Unmarshal(data, check); err != nil {
			continue
		}
		if !check.isMelangeConfig() {
			continue
		}

		packageConfig, err := config.ParseConfiguration(ctx, fi)
		if err != nil {
			return p, fmt.Errorf("failed to read package config %s: %w", fi, err)
		}
		relativeFilename, err := filepath.Rel(dir, fi)
		if err != nil {
			return p, fmt.Errorf("failed to get relative path from dir %s and file %s package config %s: %w", dir, fi, packageConfig.Package.Name, err)
		}

		nolint, err := findNoLint(fi)
		if err != nil {
			return p, fmt.Errorf("failed to read package config %s: %w", fi, err)
		}

		name := packageConfig.Package.Name
		fiBase := strings.TrimSuffix(filepath.Base(fi), filepath.Ext(fi))
		if name != fiBase {
			return p, fmt.Errorf("package name does not match file name in '%s': '%s' != '%s'", fi, name, fiBase)
		}

		if _, exists := p[name]; exists {
			return p, fmt.Errorf("package config names must be unique. Found a package called '%s' in '%s' and '%s'", name, fi, p[name].Filename)
		}

		p[name] = &Packages{
			Config:   *packageConfig,
			Filename: relativeFilename,
			Dir:      dir,
			NoLint:   nolint,
		}
	}

	return p, nil
}
