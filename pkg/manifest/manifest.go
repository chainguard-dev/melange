package manifest

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/pkg/errors"
)

type GeneratedMelangeConfig struct {
	Package              build.Package                `yaml:"package"`
	Environment          apkotypes.ImageConfiguration `yaml:"environment,omitempty"`
	Pipeline             []build.Pipeline             `yaml:"pipeline,omitempty"`
	Subpackages          []build.Subpackage           `yaml:"subpackages,omitempty"`
	Vars                 map[string]string            `yaml:"vars,omitempty"`
	GeneratedFromComment string                       `yaml:"-"`
}

func (m *GeneratedMelangeConfig) SetPackage(pkg build.Package) {
	m.Package = pkg
}

func (m *GeneratedMelangeConfig) SetEnvironment(env apkotypes.ImageConfiguration) {
	m.Environment = env
}

func (m *GeneratedMelangeConfig) SetPipeline(pipeline []build.Pipeline) {
	m.Pipeline = pipeline
}

func (m *GeneratedMelangeConfig) SetSubpackages(sub []build.Subpackage) {
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

	return nil
}
