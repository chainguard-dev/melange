package manifest

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/pkg/errors"
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
			return errors.Wrapf(err, "creating output directory %s", dir)
		}
	}

	manifestPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", m.Package.Name))
	f, err := os.Create(manifestPath)
	if err != nil {
		return errors.Wrapf(err, "creating file %s", manifestPath)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("# Generated from %s\n", m.GeneratedFromComment)); err != nil {
		return errors.Wrapf(err, "creating writing to file %s", manifestPath)
	}

	var n yaml.Node
	if err := n.Encode(m); err != nil {
		return errors.Wrapf(err, "encoding YAML to node %s", manifestPath)
	}

	if err := formatted.NewEncoder(f).AutomaticConfig().Encode(&n); err != nil {
		return errors.Wrapf(err, "encoding YAML to file %s", manifestPath)
	}

	if m.Logger != nil {
		m.Logger.Printf("Generated melange config: %s", manifestPath)
	}
	return nil
}
