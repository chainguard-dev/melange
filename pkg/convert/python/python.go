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

package python

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/manifest"
	"github.com/pkg/errors"
)

// PythonContext is the execution context for the python subcommand.
type PythonContext struct {

	// PackageName is the name of the python package to build and install
	PackageName string

	// PackageVersion is the version of python package to build and install
	PackageVersion string

	// PythonVersion is the version of python to build the package against
	PythonVersion string

	// PackageIndex - Client for talking to pypi
	PackageIndex *PackageIndex

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

	// Logger is self-explanatory
	Logger *log.Logger

	// ToGenerate is the map of dependencies that have been visited when the
	// transitive dependency list is being calculated.
	ToGenerate map[string]Package

	//Pypi Package metadata about package
	Package Package

	// ToCheck is the list of dependencies that have yet to be checked for
	// transitive dependencies.
	ToCheck []string
}

// New initialises a new PythonContext.
func New(packageName string) (PythonContext, error) {

	context := PythonContext{
		PackageName: packageName,
		Logger:      log.New(log.Writer(), "convert:python: ", log.LstdFlags|log.Lmsgprefix),
		ToGenerate:  make(map[string]Package),
	}
	return context, nil
}

// Generate is the entrypoint to generate a ruby gem melange file. It handles
// recursively finding all dependencies for a pypi package and generating a melange file
// for each.
func (c *PythonContext) Generate(ctx context.Context) error {

	c.Logger.Printf("[%s] Generating manifests", c.PackageName)

	c.PackageIndex = NewPackageIndex(c.BaseURIFormat)

	c.Logger.Printf("[%s] Retrieving Package information from %s", c.PackageName, c.PackageIndex.url)

	p, err := c.PackageIndex.Get(ctx, c.PackageName, c.PackageVersion)
	if err != nil {
		c.Logger.Printf("error getting latest for package %s - %s ", c.PackageName, err)
		return err
	}
	c.Package = *p
	// add self to check to start the find dep tree
	c.ToCheck = append(c.ToCheck, p.Info.Name)

	//download the package json metadata and find all it's deps
	err = c.findDep(ctx)
	if err != nil {
		return err
	}

	c.Logger.Printf("[%s] Generating %v files", c.PackageName, len(c.ToGenerate))

	//generate melange files for all dependencies
	for m, pack := range c.ToGenerate {
		c.Logger.Printf("[%s] Index %v Package %v ", pack.Info.Name, m, pack.Info.Name)
		c.Logger.Printf("[%s] Create manifest", pack.Info.Name)
		version := pack.Info.Version
		//if were generating the package asked for , check the version wasn't specified
		if c.PackageName == pack.Info.Name && c.PackageVersion != "" {
			version = c.PackageVersion
		}

		generated, err := c.generateManifest(ctx, pack, version)
		if err != nil {
			c.Logger.Printf("[%s] FAILED TO CREATE MANIFEST %v", pack.Info.Name, err)
			return err
		}

		err = generated.Write(c.OutDir)
		if err != nil {
			c.Logger.Printf("[%s] FAILED TO WRITE MANIFEST %v", pack.Info.Name, err)
			return err
		}
	}

	return nil
}

func stripDep(dep string) (string, error) {
	//removing all the special chars from the requirements like   "importlib-metadata (>=3.6.0) ; python_version < \"3.10\""
	re, err := regexp.Compile(`[;()\[\]!~=<>]`)
	if err != nil {
		return "", err
	}
	dep = re.ReplaceAllString(dep, " ")
	depStrip := strings.Split(dep, " ")
	return depStrip[0], nil
}

// FindDep - given a python package retrieve all its dependencies
func (c *PythonContext) findDep(ctx context.Context) error {
	if len(c.ToCheck) == 0 {
		return nil
	}

	c.Logger.Printf("[%s] Check Dependency list: %v", c.PackageName, c.ToCheck)
	c.Logger.Printf("[%s] Fetch Package Data", c.ToCheck[0])

	p, err := c.PackageIndex.GetLatest(ctx, c.ToCheck[0])
	if err != nil {
		return err
	}

	c.Logger.Printf("[%s] %s Add to generate list", c.ToCheck[0], p.Info.Name)
	c.ToCheck = c.ToCheck[1:]

	c.Logger.Printf("[%s] Check for dependencies", p.Info.Name)
	if len(p.Info.RequiresDist) == 0 {
		c.Logger.Printf("[%s] Searching source for dependencies", p.Info.Name)
		err := c.PackageIndex.CheckSourceDeps(p.Info.Name)
		if err != nil {
			return err
		}
	}

	//need to find dep here, then cycle through recursively
	for _, dep := range p.Info.RequiresDist {
		// Removing all the extras from requirements
		if strings.Contains(dep, "extra") {
			continue
		}
		dep, err = stripDep(dep)
		if err != nil {
			return err
		}
		p.Dependencies = append(p.Dependencies, "py"+c.PythonVersion+"-"+dep)
		// if dep is not already visited then check if it has deps
		_, found := c.ToGenerate[dep]
		if !found {
			c.ToCheck = append(c.ToCheck, dep)
		}
	}

	c.Logger.Printf("[%s] %v Number of deps", p.Info.Name, len(p.Dependencies))
	c.ToGenerate[p.Info.Name] = *p
	// recursive call
	return c.findDep(ctx)
}

func (c *PythonContext) generateManifest(ctx context.Context, pack Package, version string) (manifest.GeneratedMelangeConfig, error) {
	// The actual generated manifest struct
	generated := manifest.GeneratedMelangeConfig{Logger: c.Logger}

	// Generate each field in the manifest
	generated.GeneratedFromComment = pack.Info.ProjectUrl
	generated.Package = c.generatePackage(pack, version)
	generated.Environment = c.generateEnvironment(pack)

	pipelines, err := c.generatePipeline(ctx, pack, version)
	if err != nil {
		return manifest.GeneratedMelangeConfig{}, err
	}
	generated.Pipeline = pipelines

	return generated, nil
}

// generatePackage handles generating the Package field of the melange manifest
//
// It will iterate through all licenses returned by rubygems.org and place them
// under the copyright section.
func (c *PythonContext) generatePackage(pack Package, version string) config.Package {
	c.Logger.Printf("[%s] Generate Package", pack.Info.Name)

	c.Logger.Printf("[%s] Run time Deps %v", pack.Info.Name, pack.Dependencies)

	pack.Dependencies = append(pack.Dependencies, "python-"+c.PythonVersion)

	pkg := config.Package{
		Name:        fmt.Sprintf("py%s-%s", c.PythonVersion, pack.Info.Name),
		Version:     version,
		Epoch:       0,
		Description: pack.Info.Summary,
		Copyright:   []config.Copyright{},
		Dependencies: config.Dependencies{
			Runtime: pack.Dependencies,
		},
	}

	pkg.Copyright = append(pkg.Copyright, config.Copyright{
		License: pack.Info.License,
	})

	return pkg
}

// generateEnvironment handles generating the Environment field of the melange manifest
//
// It will handle adding any extra repositories and keyrings to the manifest.
func (c *PythonContext) generateEnvironment(pack Package) apkotypes.ImageConfiguration {
	c.Logger.Printf("[%s] Generate Environment", pack.Info.Name)
	pythonStandard := []string{
		"ca-certificates-bundle",
		"wolfi-base",
		"busybox",
		"build-base",
		"python-" + c.PythonVersion,            // Set the python version requested
		"py" + c.PythonVersion + "-setuptools", // Set the specific python set up tools

	}

	env := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: pythonStandard,
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
func (c *PythonContext) generatePipeline(ctx context.Context, pack Package, version string) ([]config.Pipeline, error) {

	var pipeline []config.Pipeline

	c.Logger.Printf("[%s] Generate Pipeline for version %s", pack.Info.Name, version)

	releases, ok := pack.Releases[version]
	// If the key exists
	if !ok {
		return pipeline, errors.New(fmt.Sprintf("Package version %s was not in releases for %s", version, pack.Info.Name))
	}

	var release Release
	for _, r := range releases {
		if r.PackageType == "sdist" {
			release = r
		}
	}

	if release.Url == "" {
		return pipeline, errors.New("could not find any sdist package in available releases")
	}

	artifact256SHA, err := c.PackageIndex.Client.GetArtifactSHA256(ctx, release.Url)
	if err != nil {
		c.Logger.Printf("[%s] SHA256 Generation FAILED. %v", pack.Info.Name, err)
		c.Logger.Printf("[%s]  Or try 'curl %s' to check out the API", pack.Info.Name, pack.Info.DownloadUrl)
		artifact256SHA = fmt.Sprintf("FAILED GENERATION. Investigate by going to %s", pack.Info.ProjectUrl)
	}

	if artifact256SHA != release.Digest.Sha256 {
		return pipeline, errors.New(fmt.Sprintf("Artifact 256SHA %s did not match Package data SHA256 %s",
			artifact256SHA, release.Digest.Sha256))
	}

	fetch := config.Pipeline{
		Uses: "fetch",
		With: map[string]string{
			"uri":             strings.ReplaceAll(release.Url, version, "${{package.version}}"),
			"README":          fmt.Sprintf("CONFIRM WITH: curl -L %s | sha256sum", release.Url),
			"expected-sha256": artifact256SHA,
		},
	}
	pythonBuild := config.Pipeline{
		Name: "Python Build",
		Uses: "python/build",
	}

	pythonInstall := config.Pipeline{
		Name: "Python Install",
		Uses: "python/install",
	}
	strip := config.Pipeline{
		Uses: "strip",
	}
	pipeline = append(pipeline, fetch)
	pipeline = append(pipeline, pythonBuild)
	pipeline = append(pipeline, pythonInstall)
	pipeline = append(pipeline, strip)

	return pipeline, nil
}
