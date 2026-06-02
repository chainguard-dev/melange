// Copyright 2025 Chainguard, Inc.
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
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultProjectConfigFile is the default filename for project-level configuration.
const DefaultProjectConfigFile = ".melange.yaml"

// ProjectConfig represents the top-level structure of a .melange.yaml project config file.
type ProjectConfig struct {
	Global GlobalConfig       `yaml:"global,omitempty"`
	Build  BuildSectionConfig `yaml:"build,omitempty"`
	Test   TestSectionConfig  `yaml:"test,omitempty"`
}

// GlobalConfig holds settings shared across build/test/compile subcommands.
type GlobalConfig struct {
	Runner           string        `yaml:"runner,omitempty"`
	SigningKey       string        `yaml:"signing-key,omitempty"`
	KeyringAppend    []string      `yaml:"keyring-append,omitempty"`
	RepositoryAppend []string      `yaml:"repository-append,omitempty"`
	Arch             []string      `yaml:"arch,omitempty"`
	OutDir           string        `yaml:"out-dir,omitempty"`
	CacheDir         string        `yaml:"cache-dir,omitempty"`
	CacheSource      string        `yaml:"cache-source,omitempty"`
	ApkCacheDir      string        `yaml:"apk-cache-dir,omitempty"`
	Namespace        string        `yaml:"namespace,omitempty"`
	PipelineDirs     []string      `yaml:"pipeline-dirs,omitempty"`
	SourceDir        string        `yaml:"source-dir,omitempty"`
	EnvFile          []string      `yaml:"env-file,omitempty"`
	PackageAppend    []string      `yaml:"package-append,omitempty"`
	Debug            *bool         `yaml:"debug,omitempty"`
	DebugRunner      *bool         `yaml:"debug-runner,omitempty"`
	Interactive      *bool         `yaml:"interactive,omitempty"`
	Remove           *bool         `yaml:"rm,omitempty"`
	IgnoreSignatures *bool         `yaml:"ignore-signatures,omitempty"`
	CPU              string        `yaml:"cpu,omitempty"`
	CPUModel         string        `yaml:"cpumodel,omitempty"`
	Memory           string        `yaml:"memory,omitempty"`
	Disk             string        `yaml:"disk,omitempty"`
	Timeout          time.Duration `yaml:"timeout,omitempty"`
}

// BuildSectionConfig holds build-specific settings that override GlobalConfig.
type BuildSectionConfig struct {
	GlobalConfig `yaml:",inline"`

	GenerateIndex      *bool    `yaml:"generate-index,omitempty"`
	EmptyWorkspace     *bool    `yaml:"empty-workspace,omitempty"`
	StripOriginName    *bool    `yaml:"strip-origin-name,omitempty"`
	DependencyLog      string   `yaml:"dependency-log,omitempty"`
	VarsFile           string   `yaml:"vars-file,omitempty"`
	BuildOption        []string `yaml:"build-option,omitempty"`
	CreateBuildLog     *bool    `yaml:"create-build-log,omitempty"`
	PersistLintResults *bool    `yaml:"persist-lint-results,omitempty"`
	LintRequire        []string `yaml:"lint-require,omitempty"`
	LintWarn           []string `yaml:"lint-warn,omitempty"`
	Cleanup            *bool    `yaml:"cleanup,omitempty"`
	GenerateProvenance *bool    `yaml:"generate-provenance,omitempty"`
	Libc               string   `yaml:"libc,omitempty"`
}

// TestSectionConfig holds test-specific settings that override GlobalConfig.
type TestSectionConfig struct {
	GlobalConfig `yaml:",inline"`

	TestOption        []string `yaml:"test-option,omitempty"`
	TestPackageAppend []string `yaml:"test-package-append,omitempty"`
}

// LoadProjectConfig reads and parses a .melange.yaml project config file.
// Unknown fields in the YAML will cause an error, helping catch typos.
func LoadProjectConfig(path string) (*ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading project config %s: %w", path, err)
	}

	var cfg ProjectConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing project config %s: %w", path, err)
	}

	return &cfg, nil
}

// FindProjectConfig looks for a .melange.yaml file in the current working directory.
// Returns the path if found, or an empty string if not found.
func FindProjectConfig() string {
	if _, err := os.Stat(DefaultProjectConfigFile); err == nil {
		return DefaultProjectConfigFile
	}
	return ""
}

// projectConfigKey is the context key for storing the project config.
type projectConfigKey struct{}

// WithProjectConfig returns a new context with the given project config stored in it.
func WithProjectConfig(ctx context.Context, cfg *ProjectConfig) context.Context {
	return context.WithValue(ctx, projectConfigKey{}, cfg)
}

// ProjectConfigFromContext retrieves the project config from the context, or nil if not set.
func ProjectConfigFromContext(ctx context.Context) *ProjectConfig {
	cfg, _ := ctx.Value(projectConfigKey{}).(*ProjectConfig)
	return cfg
}
