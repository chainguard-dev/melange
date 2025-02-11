package apkbuild

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	rlhttp "chainguard.dev/melange/pkg/http"
	"chainguard.dev/melange/pkg/manifest"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/convert/wolfios"
	"gitlab.alpinelinux.org/alpine/go/apkbuild"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

type Context struct {
	*NavigationMap
	OutDir                 string
	AdditionalRepositories []string
	AdditionalKeyrings     []string
	ExcludePackages        []string
	Client                 *rlhttp.RLHTTPClient
	WolfiOSPackages        map[string]bool
}
type NavigationMap struct {
	ApkConvertors map[string]ApkConvertor
	OrderedKeys   []string
}

type Dependency struct {
	Name string
}
type ApkConvertor struct {
	*apkbuild.Apkbuild
	ApkBuildRaw                      []byte
	*manifest.GeneratedMelangeConfig `yaml:"-"`
}

// New initialise including a map of existing wolfios packages
func New(ctx context.Context) (Context, error) {
	context := Context{
		NavigationMap: &NavigationMap{
			ApkConvertors: map[string]ApkConvertor{},
			OrderedKeys:   []string{},
		},

		Client: &rlhttp.RLHTTPClient{
			Client: http.DefaultClient,

			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
	}

	var err error
	wolfi := wolfios.New(http.DefaultClient, wolfios.PackageIndex)
	context.WolfiOSPackages, err = wolfi.GetWolfiPackages(ctx)
	if err != nil {
		return context, fmt.Errorf("failed to get packages from wolfi index: %w", err)
	}

	return context, nil
}

func (c Context) Generate(ctx context.Context, apkBuildURI, pkgName string) error {
	log := clog.FromContext(ctx)
	// get the contents of the APKBUILD file
	err := c.getApkBuildFile(ctx, apkBuildURI, pkgName)
	if err != nil {
		return fmt.Errorf("getting apk build file: %w", err)
	}

	// build map of dependencies
	err = c.buildMapOfDependencies(ctx, apkBuildURI, pkgName)
	if err != nil {
		return fmt.Errorf("building map of dependencies: %w", err)
	}

	// reverse map order, so we generate the lowest transitive dependency first
	// this will help to build convert configs in the correct order
	slices.Reverse(c.OrderedKeys)

	// loop over map and generate convert config for each
	for i, key := range c.OrderedKeys {
		apkConverter := c.ApkConvertors[key]

		// automatically add a fetch step to the convert config to fetch the source
		err = c.buildFetchStep(ctx, apkConverter)
		if err != nil {
			// lets not error if we can't automatically add the fetch step
			log.Errorf("skipping fetch step for %s", err.Error())
		}

		// maps the APKBUILD values to convert config
		apkConverter.mapconvert()

		// builds the convert environment configuration
		apkConverter.buildEnvironment(c.AdditionalRepositories, c.AdditionalKeyrings)

		err = apkConverter.write(ctx, strconv.Itoa(i), c.OutDir)
		if err != nil {
			return fmt.Errorf("writing convert config file: %w", err)
		}
	}

	return nil
}

func (c Context) getApkBuildFile(ctx context.Context, apkbuildURL, packageName string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", apkbuildURL, nil)
	resp, err := c.Client.Do(req)

	if err != nil {
		return fmt.Errorf("getting %s: %w", apkbuildURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non ok http response code: %v", resp.StatusCode)
	}
	apkbuildFile := apkbuild.NewApkbuildFile(packageName, resp.Body)

	parsedApkBuild, err := apkbuild.Parse(apkbuildFile, nil)

	if err != nil {
		return fmt.Errorf("failed to parse apkbuild %s: %w", apkbuildURL, err)
	}

	c.ApkConvertors[packageName] = ApkConvertor{
		Apkbuild: &parsedApkBuild,
		GeneratedMelangeConfig: &manifest.GeneratedMelangeConfig{
			GeneratedFromComment: apkbuildURL,
		},
	}
	c.ApkConvertors[packageName].GeneratedMelangeConfig.Package = config.Package{
		Epoch: 0,
	}
	c.OrderedKeys = append(c.OrderedKeys, packageName)
	return nil
}

// recursively add dependencies, and their dependencies to our map
func (c Context) buildMapOfDependencies(ctx context.Context, apkBuildURI, pkgName string) error {
	log := clog.FromContext(ctx)
	convertor, exists := c.ApkConvertors[pkgName]
	if !exists {
		return fmt.Errorf("no top level apk convertor found for URI %s", apkBuildURI)
	}

	dependencies := c.transitiveDependencyList(convertor)

	// recursively loop round and add any missing dependencies to the map
	for _, dep := range dependencies {
		if strings.TrimSpace(dep) == "" {
			continue
		}

		// remove -dev or -static from dependency name when looking up matching APKBUILD
		dep = strings.TrimSuffix(dep, "-dev")
		dep = strings.TrimSuffix(dep, "-static")

		// skip if we already have a package in wolfi-os repository
		log.Infof("checking if %s is all ready in wolfi os", dep)
		if c.WolfiOSPackages[dep] {
			log.Infof("yes it is, skipping...")
			continue
		}

		// if dependency is in the list of packages configured one the CLI to exclude, let's skip
		log.Infof("checking if %s is in %s", dep, strings.Join(c.ExcludePackages, " "))
		if contains(c.ExcludePackages, dep) {
			log.Infof("yes it is, skipping...")
			continue
		}

		// using the same base URI switch the existing package name for the dependency and get related APKBUILD
		dependencyApkBuildURI := strings.ReplaceAll(apkBuildURI, convertor.Apkbuild.Pkgname, dep)

		// if we don't already have this dependency in the map, go get it
		_, exists = c.ApkConvertors[dep]
		if exists {
			// move dependency to the end of our ordered keys to ensure we generate melange configs in the correct order
			// TODO lets switch this to use https://github.com/wolfi-dev/dag
			var reorderdKeys []string
			for _, key := range c.OrderedKeys {
				if key != dep {
					reorderdKeys = append(reorderdKeys, key)
				}
			}

			reorderdKeys = append(reorderdKeys, dep)
			c.OrderedKeys = reorderdKeys
		} else {
			// if the dependency doesn't already exist let's go and get it
			err := c.getApkBuildFile(ctx, dependencyApkBuildURI, dep)
			if err != nil {
				// log and skip this dependency if there's an issue getting the APKBUILD as we are guessing the location of the APKBUILD
				log.Infof("failed to get APKBUILD %s", dependencyApkBuildURI)
				continue
			}

			err = c.buildMapOfDependencies(ctx, dependencyApkBuildURI, dep)
			if err != nil {
				return fmt.Errorf("building map of dependencies: %w", err)
			}
		}
	}
	return nil
}

func (c Context) transitiveDependencyList(convertor ApkConvertor) []string {
	var dependencies []string
	for _, depends := range convertor.Apkbuild.Depends {
		if !slices.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	for _, depends := range convertor.Apkbuild.Makedepends {
		if !slices.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	for _, depends := range convertor.Apkbuild.DependsDev {
		if !slices.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	return dependencies
}

// Helper function to check if a URL belongs to GitHub and extract the owner/repo
func getGitHubIdentifierFromURL(packageURL string) (string, bool) {
	u, err := url.Parse(packageURL)
	if err != nil || u.Host != "github.com" {
		// Not a GitHub URL
		return "", false
	}
	// Extract the owner and repo from the URL path
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		// Invalid GitHub URL format
		return "", false
	}
	owner, repo := parts[0], parts[1]
	return path.Join(owner, repo), true
}

// Helper function to set up the update block based on the fetch source
func (c *Context) setupUpdateBlock(packageURL string, packageVersion string, converter *ApkConvertor) {
	// Check if the package was fetched from GitHub
	if identifier, isGitHub := getGitHubIdentifierFromURL(packageURL); isGitHub {

		// Enable GitHub monitoring
		converter.GeneratedMelangeConfig.Update = config.Update{
			Enabled: true,
			GitHubMonitor: &config.GitHubMonitor{
				Identifier: identifier, // Set the owner/repo identifier
				// To add logic to improve this check
				// StripPrefix:     "v",        // Strip "v" from tags like "v1.2.3"
				// TagFilterPrefix: "v",        // Filter tags with a "v" prefix
			},
		}
	} else {
		// Fallback to release-monitoring.org if it's not a GitHub package
		converter.GeneratedMelangeConfig.Update = config.Update{
			Enabled: true,
			ReleaseMonitor: &config.ReleaseMonitor{
				Identifier: 12345, // Example ID, replace this with actual logic to get the ID
			},
		}
	}
}

// Helper function to fetch the commit hash for a specific tag from a GitHub repository
func getCommitForTagFromGitHub(repoURL, tag string) (string, error) {
	// Parse the repository URL to extract the owner and repo name
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("invalid repository URL: %w", err)
	}

	// Assume the URL is in the form of "https://github.com/owner/repo"
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid GitHub repository URL format")
	}
	owner, repo := parts[0], parts[1]

	// Build the API URL for fetching the tags in the repository
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/tags/%s", owner, repo, tag)

	// Send the request to the GitHub API
	resp, err := http.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("error fetching tag information: %w", err)
	}
	defer resp.Body.Close()

	// Parse the JSON response
	var tagResponse struct {
		Object struct {
			Sha string `json:"sha"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagResponse); err != nil {
		return "", fmt.Errorf("error parsing GitHub response: %w", err)
	}

	// Return the commit SHA associated with the tag
	return tagResponse.Object.Sha, nil
}

// add pipeline fetch steps, validate checksums and generate mconvert expected sha
func (c *Context) buildFetchStep(ctx context.Context, converter ApkConvertor) error {
	log := clog.FromContext(ctx)

	apkBuild := converter.Apkbuild

	// Check if the package URL is available
	if apkBuild.Url != "" {
		// Check if the URL belongs to GitHub
		if _, isGitHub := getGitHubIdentifierFromURL(apkBuild.Url); isGitHub {
			// GitHub URL, proceed with git-checkout pipeline
			_, err := url.ParseRequestURI(apkBuild.Url)
			if err != nil {
				return fmt.Errorf("parsing URI %s: %w", apkBuild.Url, err)
			}

			// Fetch the commit hash for the package version tag
			expectedCommit, err := getCommitForTagFromGitHub(apkBuild.Url, apkBuild.Pkgver) // Using the package version as the tag
			if err != nil {
				return fmt.Errorf("error fetching commit for tag: %w", err)
			}

			// Create a basic git-checkout pipeline
			pipeline := config.Pipeline{
				Uses: "melange/git-checkout",
				With: map[string]string{
					"repository":      apkBuild.Url,
					"tag":             "${{package.version}}", // The version as the tag or branch reference
					"expected-commit": expectedCommit,         // Use the dynamically fetched commit
				},
			}

			// Add the pipeline to the generated configuration
			converter.GeneratedMelangeConfig.Pipeline = append(converter.GeneratedMelangeConfig.Pipeline, pipeline)

			// Set up the update block based on the package source (GitHub or release-monitoring)
			c.setupUpdateBlock(apkBuild.Url, apkBuild.Pkgver, &converter)

			log.Infof("Using git-checkout pipeline for package %s with repository %s and expected commit %s", converter.Pkgname, apkBuild.Url, expectedCommit)
			return nil
		} else {
			log.Infof("Package URL is not from GitHub, falling back to tar.gz method")
		}
	}

	// Fallback to fetching tar.gz if URL is missing or not GitHub
	log.Infof("No valid GitHub URL found for package %s, using tar.gz method", converter.Pkgname)
	if len(apkBuild.Source) == 0 {
		log.Infof("skip adding pipeline for package %s, no source URL found", converter.Pkgname)
		return nil
	}
	if apkBuild.Pkgver == "" {
		return fmt.Errorf("no package version")
	}

	// Loop over sources and add fetch steps for tarball
	for _, source := range apkBuild.Source {
		location := source.Location

		_, err := url.ParseRequestURI(location)
		if err != nil {
			return fmt.Errorf("parsing URI %s: %w", location, err)
		}

		// Create a request using standard http.NewRequestWithContext
		req, err := http.NewRequestWithContext(ctx, "GET", location, nil)
		if err != nil {
			return fmt.Errorf("creating request for URI %s: %w", location, err)
		}

		// Use RLHTTPClient to send the request with rate limiting
		resp, err := c.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed getting URI %s: %w", location, err)
		}
		defer resp.Body.Close()

		failed := false
		if resp.StatusCode != http.StatusOK {
			log.Infof("non ok http response for URI %s code: %v", location, resp.StatusCode)
			failed = true
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed getting URI %s: %w", location, err)
		}

		var expectedSha string
		if !failed {
			// Validate the source matches the sha512 in the APKBUILD
			validated := false
			for _, shas := range apkBuild.Sha512sums {
				if shas.Source == source.Filename {
					h512 := sha512.New()
					h512.Write(b)

					if shas.Hash == fmt.Sprintf("%x", h512.Sum(nil)) {
						validated = true
					}
				}
			}

			// Now generate the 256 sha for the convert config
			if !validated {
				expectedSha = "SHA512 DOES NOT MATCH SOURCE - VALIDATE MANUALLY"
				log.Infof("source %s expected sha512 do not match!", source.Filename)
			} else {
				h256 := sha256.New()
				h256.Write(b)

				expectedSha = fmt.Sprintf("%x", h256.Sum(nil))
			}
		} else {
			expectedSha = "FIXME - SOURCE URL NOT VALID"
		}

		// Fallback to using the fetch pipeline with tarball location
		pipeline := config.Pipeline{
			Uses: "fetch",
			With: map[string]string{
				"uri":             strings.ReplaceAll(location, apkBuild.Pkgver, "${{package.version}}"),
				"expected-sha256": expectedSha,
			},
		}
		converter.GeneratedMelangeConfig.Pipeline = append(converter.GeneratedMelangeConfig.Pipeline, pipeline)

	}

	return nil
}

// maps APKBUILD values to mconvert
func (c ApkConvertor) mapconvert() {
	c.GeneratedMelangeConfig.Package.Name = c.Apkbuild.Pkgname
	c.GeneratedMelangeConfig.Package.Description = c.Apkbuild.Pkgdesc
	c.GeneratedMelangeConfig.Package.Version = c.Apkbuild.Pkgver
	c.GeneratedMelangeConfig.Package.Epoch = 0

	// Add the version-check test block
	testPipeline := config.Pipeline{
		Name: "Verify " + c.Apkbuild.Pkgname + " installation, please improve the test as needed",
		Runs: fmt.Sprintf("%s --version || exit 1", c.Apkbuild.Pkgname), // Basic version check
	}

	// Add the test block to the generated config
	testBlock := &config.Test{
		Pipeline: []config.Pipeline{
			testPipeline,
		},
	}

	// Add the test block to the configuration
	c.GeneratedMelangeConfig.Test = testBlock

	copyright := config.Copyright{
		License: c.Apkbuild.License,
	}
	c.GeneratedMelangeConfig.Package.Copyright = append(c.GeneratedMelangeConfig.Package.Copyright, copyright)

	// triggers
	if c.Apkbuild.Triggers != nil {
		scriptlets := config.Scriptlets{
			Trigger: config.Trigger{
				Paths:  []string{"FIXME"},
				Script: "FIXME",
			},
		}
		c.GeneratedMelangeConfig.Package.Scriptlets = &scriptlets
	}

	// if c.Apkbuild.Funcs["build"] != nil {
	//	// todo lets check the command and add the correct cmake | make | meson mconvert pipelines
	//	//build := c.Apkbuild.Funcs["build"]
	//}

	// switch c.Apkbuild.BuilderType {
	//
	// case BuilderTypeCMake:
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/configure"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/build"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/install"})
	//
	// case BuilderTypeMeson:
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/configure"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/compile"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/install"})
	//
	// case BuilderTypeMake:
	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "autoconf/configure"})
	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "autoconf/make"})
	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "autoconf/make-install"})
	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "strip"})

	//default:
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "# FIXME"})
	//
	//}

	for _, subPackage := range c.Apkbuild.Subpackages {
		subpackage := config.Subpackage{
			Name: strings.Replace(subPackage.Subpkgname, "$pkgname", c.Apkbuild.Pkgname, 1),
		}

		// generate subpackages based on the subpackages defined in the APKBUILD
		var ext string
		// parts := strings.Split(subPackage.Subpkgname, "-")

		i := strings.LastIndex(subPackage.Subpkgname, "-")
		if i > 0 {
			suffix := subPackage.Subpkgname[i+1:]

			switch suffix {
			case "doc":
				ext = "manpages"
			case "static":
				ext = "static"
			case "dev":
				ext = "dev"
				subpackage.Dependencies = config.Dependencies{
					Runtime: []string{c.Apkbuild.Pkgname},
				}
				// include dev dependencies in the dev runtime
				for _, dependsDev := range c.Apkbuild.DependsDev {
					subpackage.Dependencies.Runtime = append(subpackage.Dependencies.Runtime, dependsDev.Pkgname)
				}
				for _, depends := range c.Apkbuild.Depends {
					subpackage.Dependencies.Runtime = append(subpackage.Dependencies.Runtime, depends.Pkgname)
				}
			default:
				// if we don't recognise the extension make it obvious user needs to manually fix the config
				ext = "FIXME"
			}

			subpackage.Pipeline = []config.Pipeline{{Uses: "split/" + ext}}
			subpackage.Description = c.Apkbuild.Pkgname + " " + ext
		} else {
			// if we don't recognise the extension make it obvious user needs to manually fix the mconvert config
			subpackage.Pipeline = []config.Pipeline{{Runs: "FIXME"}}
		}

		c.GeneratedMelangeConfig.Subpackages = append(c.GeneratedMelangeConfig.Subpackages, subpackage)
	}
}

// adds a mconvert environment section
func (c ApkConvertor) buildEnvironment(additionalRepositories, additionalKeyrings []string) {
	// wolfi-os base environment
	env := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: []string{
				"build-base",
				"busybox",
				"ca-certificates-bundle",
			},
		},
	}

	env.Contents.BuildRepositories = append(env.Contents.BuildRepositories, additionalRepositories...)
	env.Contents.Keyring = append(env.Contents.Keyring, additionalKeyrings...)
	for _, makedepend := range c.Apkbuild.Makedepends {
		env.Contents.Packages = append(env.Contents.Packages, makedepend.Pkgname)
	}

	for _, dependsDev := range c.Apkbuild.DependsDev {
		d := dependsDev.Pkgname
		if !strings.HasSuffix(d, "-dev") {
			d += "-dev"
		}
		if !contains(env.Contents.Packages, d) {
			env.Contents.Packages = append(env.Contents.Packages, d)
		}
	}

	for _, depends := range c.Apkbuild.Depends {
		if !contains(env.Contents.Packages, depends.Pkgname) {
			env.Contents.Packages = append(env.Contents.Packages, depends.Pkgname)
		}
	}

	for i, p := range env.Contents.Packages {
		if p == "$depends_dev" {
			env.Contents.Packages = slices.Delete(env.Contents.Packages, i, i+1)
			break
		}
	}
	c.GeneratedMelangeConfig.Environment = env
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func (c ApkConvertor) write(ctx context.Context, orderNumber, outdir string) error {
	// Ensure output directory exists
	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		err = os.MkdirAll(outdir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("creating output directory %s: %w", outdir, err)
		}
	}

	// Prepare the file path for the YAML output
	manifestFile := filepath.Join(outdir, fmt.Sprintf("%s0-%s.yaml", orderNumber, c.Apkbuild.Pkgname))
	f, err := os.Create(manifestFile)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", manifestFile, err)
	}
	defer f.Close()

	// Write the initial comment to the YAML file
	if _, err := f.WriteString(fmt.Sprintf("# Generated from %s\n", c.GeneratedMelangeConfig.GeneratedFromComment)); err != nil {
		return fmt.Errorf("writing to file %s: %w", manifestFile, err)
	}

	// Marshal the configuration into a YAML node for formatting
	var n yaml.Node
	if err := n.Encode(c.GeneratedMelangeConfig); err != nil {
		return fmt.Errorf("encoding YAML to node: %w", err)
	}

	// Use the formatted YAML encoder to write the YAML data
	if err := formatted.NewEncoder(f).AutomaticConfig().Encode(&n); err != nil {
		return fmt.Errorf("encoding formatted YAML to file %s: %w", manifestFile, err)
	}

	clog.FromContext(ctx).Infof("Generated melange config with update block: %s", manifestFile)
	return nil
}
