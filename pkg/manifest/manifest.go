package manifest

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"gopkg.in/yaml.v3"
)

type GeneratedMelangeConfig struct {
	config.Configuration `yaml:",inline"`
	GeneratedFromComment string      `yaml:"-"`
	Logger               *log.Logger `yaml:"-"`
}

func (m *GeneratedMelangeConfig) SetPackage(pkg config.Package) {
	m.Package = pkg
}

func (m *GeneratedMelangeConfig) SetEnvironment(env apkotypes.ImageConfiguration) {
	m.Environment = env
}

func (m *GeneratedMelangeConfig) SetPipeline(pipeline []config.Pipeline) {
	m.Pipeline = pipeline
}

func (m *GeneratedMelangeConfig) SetSubpackages(sub []config.Subpackage) {
	m.Subpackages = sub
}

func (m *GeneratedMelangeConfig) SetGeneratedFromComment(comment string) {
	m.GeneratedFromComment = comment
}

func (m *GeneratedMelangeConfig) Write(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("creating output directory %s: %w", dir, err)
		}
	}

	manifestPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", m.Package.Name))
	f, err := os.Create(manifestPath)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", manifestPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("# Generated from %s\n", m.GeneratedFromComment)); err != nil {
		return fmt.Errorf("creating writing to file %s: %w", manifestPath, err)
	}

	var n yaml.Node
	if err := n.Encode(m); err != nil {
		return fmt.Errorf("encoding YAML to node %s: %w", manifestPath, err)
	}

	if err := formatted.NewEncoder(f).AutomaticConfig().Encode(&n); err != nil {
		return fmt.Errorf("encoding YAML to file %s: %w", manifestPath, err)
	}

	if m.Logger != nil {
		m.Logger.Printf("Generated melange config: %s", manifestPath)
	}
	return nil
}
