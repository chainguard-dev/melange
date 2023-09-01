package manifest

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/pkg/errors"
)

type GeneratedMelangeConfig struct {
	Package              config.Package               `yaml:"package"`
	Environment          apkotypes.ImageConfiguration `yaml:"environment,omitempty"`
	Pipeline             []config.Pipeline            `yaml:"pipeline,omitempty"`
	Subpackages          []config.Subpackage          `yaml:"subpackages,omitempty"`
	Vars                 map[string]string            `yaml:"vars,omitempty"`
	Update               config.Update                `yaml:"update,omitempty"`
	GeneratedFromComment string                       `yaml:"-"`
	Logger               *log.Logger                  `yaml:"-"`
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

	_, err = f.WriteString(fmt.Sprintf("# Generated from %s\n", m.GeneratedFromComment))
	if err != nil {
		return errors.Wrapf(err, "creating writing to file %s", manifestPath)
	}

	ye := yaml.NewEncoder(f)
	defer ye.Close()

	if err := ye.Encode(m); err != nil {
		return errors.Wrapf(err, "creating writing to file %s", manifestPath)
	}

	if m.Logger != nil {
		m.Logger.Printf("Generated melange config: %s", manifestPath)
	}
	return nil
}
