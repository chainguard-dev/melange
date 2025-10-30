package manifest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
)

type GeneratedMelangeConfig struct {
	config.Configuration `yaml:",inline"`
	GeneratedFromComment string `yaml:"-"`
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

func (m *GeneratedMelangeConfig) Write(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0o755)
		if err != nil {
			return fmt.Errorf("creating output directory %s: %w", dir, err)
		}
	}

	manifestPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", m.Package.Name))
	f, err := os.Create(manifestPath) // #nosec G304 - Writing manifest to output directory
	if err != nil {
		return fmt.Errorf("creating file %s: %w", manifestPath, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "# Generated from %s\n", m.GeneratedFromComment); err != nil {
		return fmt.Errorf("creating writing to file %s: %w", manifestPath, err)
	}

	var n yaml.Node
	if err := n.Encode(m); err != nil {
		return fmt.Errorf("encoding YAML to node %s: %w", manifestPath, err)
	}

	if err := formatted.NewEncoder(f).AutomaticConfig().Encode(&n); err != nil {
		return fmt.Errorf("encoding YAML to file %s: %w", manifestPath, err)
	}

	clog.FromContext(ctx).Infof("Generated melange config: %s", manifestPath)
	return nil
}
