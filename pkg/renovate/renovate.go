// Copyright 2022 Chainguard, Inc.
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

package renovate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/chainguard-dev/yam/pkg/util"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"chainguard.dev/melange/pkg/config"
)

// Context contains the default settings for renovations.
type Context struct {
	ConfigFile string
}

type Option func(ctx *Context) error

// WithConfig sets the config file to do renovations on.
func WithConfig(configFile string) Option {
	return func(ctx *Context) error {
		ctx.ConfigFile = configFile
		return nil
	}
}

// New creates a new renovation context.
func New(opts ...Option) (*Context, error) {
	c := Context{}

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// RenovationContext encapsulates state relating to an
// ongoing renovation.
type RenovationContext struct {
	Context       *Context
	Configuration *config.Configuration
	Vars          map[string]string
}

// Renovator performs a renovation.
type Renovator func(ctx context.Context, rc *RenovationContext) error

// Renovate loads a config file, applies a chain of Renovators
// to perform a renovation, and writes the result back.
func (c *Context) Renovate(ctx context.Context, renovators ...Renovator) error {
	rc := RenovationContext{Context: c}

	if err := rc.LoadConfig(ctx); err != nil {
		return err
	}

	for _, ren := range renovators {
		if err := ren(ctx, &rc); err != nil {
			return err
		}
	}

	if err := rc.WriteConfig(); err != nil {
		return err
	}

	return nil
}

// LoadConfig loads the configuration data into an AST for renovation.
func (rc *RenovationContext) LoadConfig(ctx context.Context) error {
	cfg, err := config.ParseConfiguration(ctx, rc.Context.ConfigFile)
	if err != nil {
		return err
	}

	vars, err := cfg.GetVarsFromConfig()
	if err != nil {
		return err
	}

	// These are probably sufficient for now.
	// TODO(Elizafox): Enable cross-arch bumping
	vars[config.SubstitutionPackageName] = cfg.Package.Name
	vars[config.SubstitutionPackageVersion] = cfg.Package.Version
	vars[config.SubstitutionPackageEpoch] = strconv.FormatUint(cfg.Package.Epoch, 10)
	vars[config.SubstitutionBuildArch] = apko_types.ParseArchitecture(runtime.GOARCH).ToAPK()
	vars[config.SubstitutionBuildGoArch] = apko_types.ParseArchitecture(runtime.GOARCH).String()

	err = cfg.PerformVarSubstitutions(vars)
	if err != nil {
		return err
	}

	rc.Configuration = cfg
	rc.Vars = vars
	return nil
}

// WriteConfig writes the modified configuration data back to the config
// file.
func (rc *RenovationContext) WriteConfig() error {
	configFile, err := os.Create(rc.Context.ConfigFile)
	if err != nil {
		return err
	}
	defer configFile.Close()

	enc, err := rc.encoder(configFile)
	if err != nil {
		return err
	}

	if err := enc.Encode(rc.Configuration.Root().Content[0]); err != nil {
		return err
	}

	return nil
}

// encoder returns a yam encoder configured from the nearest .yam.yaml at or
// above the config file's directory, so the output follows the formatting
// rules of the repository the file lives in rather than whatever happens to
// be in the process working directory. Callers such as bots run with a
// working directory outside the checkout; without this they wrote with no
// gap expressions, which drops the blank line before a comment block and
// makes yaml.v3 re-attach the block to the next item on the next parse.
// When no .yam.yaml is found, fall back to yam's own lookup in the working
// directory to preserve the existing CLI behaviour.
func (rc *RenovationContext) encoder(w io.Writer) (formatted.Encoder, error) {
	dir, err := filepath.Abs(filepath.Dir(rc.Context.ConfigFile))
	if err != nil {
		return formatted.Encoder{}, err
	}

	for {
		path := filepath.Join(dir, util.ConfigFileName)
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			opts, err := formatted.ReadConfigFrom(f)
			if err != nil {
				return formatted.Encoder{}, fmt.Errorf("reading %s: %w", path, err)
			}
			if opts.Indent == 0 {
				// Match the yam CLI default when the config omits indent.
				opts.Indent = 2
			}
			return formatted.NewEncoder(w).UseOptions(*opts)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return formatted.Encoder{}, err
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return formatted.NewEncoder(w).AutomaticConfig(), nil
		}
		dir = parent
	}
}
