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

package gem

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	rlhttp "chainguard.dev/melange/pkg/http"
	"chainguard.dev/melange/pkg/manifest"

	"github.com/pkg/errors"
	"golang.org/x/time/rate"
)

const (
	DefaultRubyVersion   = "3.2"
	DefaultBaseURIFormat = "https://rubygems.org/api/v1/gems/%s.json"
)

// GemContext is the execution context for the gem subcommand.
type GemContext struct {
	// RubyVersion is the version of ruby used when generating melange files.
	RubyVersion string

	// OutDir is the output directory for the generated melange files.
	OutDir string

	// BaseURIFormat is the base URI which should contain a %s for the
	// package name.
	BaseURIFormat string

	// AdditionalRepositories contains any additional apk repos to add
	// to the manifest.
	AdditionalRepositories []string

	// AdditionalKeyrings contains any additional apk keys to add
	// to the manifest.
	AdditionalKeyrings []string

	// Client is a rate limited client used to make http calls
	Client *rlhttp.RLHTTPClient

	// Logger is self-explanatory
	Logger *log.Logger

	// ToGenerate is the map of dependencies that have been visited when the
	// transitive dependency list is being calculated.
	ToGenerate map[string]GemMeta

	// ToCheck is the list of dependencies that have yet to be checked for
	// transitive dependencies.
	ToCheck []string
}

// GemMeta is the json response from rubygems.org
type GemMeta struct {
	Name          string              `json:"name"`
	Version       string              `json:"version"`
	Info          string              `json:"info"`
	Licenses      []string            `json:"licenses"`
	SourceCodeURI string              `json:"source_code_uri"`
	HomepageURI   string              `json:"homepage_uri"`
	Dependencies  GemMetaDependencies `json:"dependencies"`

	// RepoURI is not a part of the gem metadata returned by rubygems.org,
	// however it is intended to be the source of truth for the repository
	// URI since some gems use HomepageURI and some use SourceCodeURI.
	RepoURI string `json:"-"`
}

type GemMetaDependencies struct {
	Runtime []GemMetaDependency `json:"runtime"`
}

type GemMetaDependency struct {
	Name         string `json:"name"`
	Requirements string `json:"requirements"`
}

// TODO: Why isn't this pulled in from melange/build?
type ImageContents struct {
	Repositories []string `yaml:"repositories,omitempty"`
	Keyring      []string `yaml:"keyring,omitempty"`
	Packages     []string `yaml:"packages,omitempty"`
}

// New initialises a new GemContext.
//
//	TODO: Add a check for ruby-* packages in wolfios once the name has been \
//		standardised. Otherwise, we risk skipping ruby packages if the apk \
//		exists but is not actually a ruby gem.
func New() (GemContext, error) {
	context := GemContext{
		Client: &rlhttp.RLHTTPClient{
			Client: http.DefaultClient,

			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
		Logger:     log.New(log.Writer(), "mconvert:gem: ", log.LstdFlags|log.Lmsgprefix),
		ToGenerate: make(map[string]GemMeta),
	}
	return context, nil
}

// Generate is the entrypoint to generate a ruby gem melange file. It handles
// recursively finding all dependencies for a gem and generating a melange file
// for each.
func (c *GemContext) Generate(packageName string) error {
	c.ToCheck = []string{packageName}

	err := c.findDependencies()
	if err != nil {
		return err
	}

	for _, meta := range c.ToGenerate {
		c.Logger.Printf("[%s] Create manifest", meta.Name)
		generated, err := c.generateManifest(meta)
		if err != nil {
			c.Logger.Printf("[%s] FAILED TO CREATE MANIFEST %v", meta.Name, err)
		}

		err = generated.Write(c.OutDir)
		if err != nil {
			c.Logger.Printf("[%s] FAILED TO WRITE MANIFEST %v", meta.Name, err)
		}
	}

	return nil
}

// findDependencies recursively checks each runtime dependency for any extra
// dependencies.
//
// All dependencies that are found get placed in the ToCheck slice (if
// they have not already been visited) where the await their turn to be visited.
//
// Once a dependency in the ToCheck slice is visited, it gets removed from
// the ToCheck slice and placed into the ToGenerate map.
//
// Once the ToCheck array is empty, the ToGenerate map will contain the list
// of all transitive dependencies.
//
// TODO: Interpret the Version and use to query for gem
func (c *GemContext) findDependencies() error {
	if len(c.ToCheck) < 1 {
		return nil
	}

	c.Logger.Printf("Dependency list: %v", c.ToCheck)

	c.Logger.Printf("[%s] Fetch metadata", c.ToCheck[0])
	url := fmt.Sprintf(c.BaseURIFormat, c.ToCheck[0])
	g, err := c.getGemMeta(url)
	if err != nil {
		return err
	}
	c.Logger.Printf("[%s] Add to generate list", c.ToCheck[0])
	c.ToGenerate[c.ToCheck[0]] = g
	c.ToCheck = c.ToCheck[1:]

	c.Logger.Printf("[%s] Check for dependencies", g.Name)
	for _, dep := range g.Dependencies.Runtime {
		// if dep is not already visited then check if it has deps
		_, found := c.ToGenerate[dep.Name]
		if !found {
			c.ToCheck = append(c.ToCheck, dep.Name)
		}
	}

	// recursive call
	return c.findDependencies()
}

// getGemMeta handles talking to rubygems.org and pulling the ruby gem metadata
//
// It will handle converting the json into GemMeta struct which gets returned
// to the caller.
func (c *GemContext) getGemMeta(gemURI string) (GemMeta, error) {
	req, err := http.NewRequest("GET", gemURI, nil)
	if err != nil {
		return GemMeta{}, errors.Wrapf(err, "creating request for %s", gemURI)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return GemMeta{}, errors.Wrapf(err, "getting %s", gemURI)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GemMeta{}, errors.Wrapf(err, "%d when getting %s", resp.StatusCode, gemURI)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GemMeta{}, errors.Wrap(err, "reading body")
	}

	var g GemMeta
	err = json.Unmarshal(body, &g)
	if err != nil {
		return GemMeta{}, errors.Wrap(err, "unmarshaling gem metadata")
	}

	// Try to set the right Uri to the repo, sometimes gems use homepage instead of source code.
	g.RepoURI = g.SourceCodeURI
	if g.SourceCodeURI == "" {
		g.RepoURI = g.HomepageURI
	}

	return g, nil
}

// generateManifest handles actually composing the melange manifest.
//
// It will return a fully composed melange manifest. Errors in the composing
// process are handled in each section as it is being composed. Any error that
// occurs should not stop the process, instead it should indicate in the logs
// and generated melange manifest what happened. That way the generation process
// can continue and discrepancies can be handled later.
func (c *GemContext) generateManifest(g GemMeta) (manifest.GeneratedMelangeConfig, error) {

	// The actual generated manifest struct
	generated := manifest.GeneratedMelangeConfig{}

	// Generate each field in the manifest
	generated.GeneratedFromComment = g.RepoURI
	generated.Package = c.generatePackage(g)
	generated.Environment = c.generateEnvironment()
	generated.Vars = c.generateVars(g)
	generated.Pipeline = c.generatePipeline(g)

	return generated, nil
}

// generatePackage handles generating the Package field of the melange manifest
//
// It will iterate through all licenses returned by rubygems.org and place them
// under the copyright section.
func (c *GemContext) generatePackage(g GemMeta) build.Package {
	pkg := build.Package{
		Epoch:       0,
		Name:        fmt.Sprintf("ruby%s-%s", c.RubyVersion, g.Name),
		Description: g.Info,
		Version:     g.Version,
		Copyright:   []build.Copyright{},
		Dependencies: build.Dependencies{
			Runtime: []string{},
		},
	}
	for _, license := range g.Licenses {
		pkg.Copyright = append(pkg.Copyright, build.Copyright{
			License: license,
		})
	}
	for _, dep := range g.Dependencies.Runtime {
		pkg.Dependencies.Runtime = append(pkg.Dependencies.Runtime, fmt.Sprintf("ruby%s-%s", c.RubyVersion, dep.Name))
	}

	return pkg
}

// generateEnvironment handles generating the Environment field of the melange manifest
//
// It will handle adding any extra repositories and keyrings to the manifest.
func (c *GemContext) generateEnvironment() apkotypes.ImageConfiguration {
	env := apkotypes.ImageConfiguration{
		Contents: ImageContents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
			Packages: []string{
				"ca-certificates-bundle",
				fmt.Sprintf("ruby-%s", c.RubyVersion),
				fmt.Sprintf("ruby-%s-dev", c.RubyVersion),
				"build-base",
				"busybox",
				"git",
			},
		},
	}

	if len(c.AdditionalRepositories) > 0 {
		env.Contents.Repositories = append(env.Contents.Repositories, c.AdditionalRepositories...)
	}

	if len(c.AdditionalKeyrings) > 0 {
		env.Contents.Keyring = append(env.Contents.Keyring, c.AdditionalKeyrings...)
	}

	return env
}

// generatePipeline handles generating the Pipeline field of the melange manifest
//
// It currently consists of three pipelines
// 1. fetch - fetches the artifact
// 2. patch - generates the patch pipeline in case it's needed
// 3. runs - runs the actual build and install
//
// The sha256 of the artifact should be generated automatically. If the
// generation fails for any reason it will spit logs and place a default string
// in the manifest and move on.
func (c *GemContext) generatePipeline(g GemMeta) []build.Pipeline {
	artifactURI := fmt.Sprintf("%s/archive/refs/tags/%s", g.RepoURI, fmt.Sprintf("v%s.tar.gz", g.Version))

	artifactSHA, err := c.getGemArtifactSHA(artifactURI)
	if err != nil {
		c.Logger.Printf("[%s] SHA256 Generation FAILED. %v", g.Name, err)
		c.Logger.Printf("[%s]  Investigate by going to https://rubygems.org/gems/%s", g.Name, g.Name)
		c.Logger.Printf("[%s]  Or try 'curl %s' to check out the API", g.Name, fmt.Sprintf(c.BaseURIFormat, g.Name))
		artifactSHA = fmt.Sprintf("FAILED GENERATION. Investigate by going to https://rubygems.org/gems/%s", g.Name)
	}

	pipeline := []build.Pipeline{
		{
			Uses: "fetch",
			With: map[string]string{
				"uri":             strings.ReplaceAll(artifactURI, g.Version, "${{package.version}}"),
				"README":          fmt.Sprintf("CONFIRM WITH: curl -L %s | sha256sum", artifactURI),
				"expected-sha256": artifactSHA,
			},
		}, {
			Uses: "patch",
			With: map[string]string{
				"README":  "This is only required if the gemspec is using a signing key",
				"patches": "patches/${{package.name}}.patch",
			},
		}, {
			Uses: "ruby/build",
			With: map[string]string{
				"gem": "${{vars.gem}}",
			},
		}, {
			Uses: "ruby/install",
			With: map[string]string{
				"gem":     "${{vars.gem}}",
				"version": "${{package.version}}",
			},
		}, {
			Uses: "ruby/clean",
		},
	}
	return pipeline
}

// getGemArtifactSHA attempts to pull the specified artifact and generate a
// sha256 hash of it.
//
// On success, it will return the sha256 hash as a string.
func (c *GemContext) getGemArtifactSHA(artifactURI string) (string, error) {
	req, err := http.NewRequest("GET", artifactURI, nil)
	if err != nil {
		return "", errors.Wrapf(err, "creating request for %s", artifactURI)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "getting %s", artifactURI)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%d when getting %s", resp.StatusCode, artifactURI)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading body")
	}

	h256 := sha256.New()
	h256.Write(body)
	return fmt.Sprintf("%x", h256.Sum(nil)), nil
}

// generateVars handles generating the Vars field of the melange manifest
func (c *GemContext) generateVars(g GemMeta) map[string]string {
	return map[string]string{
		"gem": g.Name,
	}
}
