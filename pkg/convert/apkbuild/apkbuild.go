package apkbuild

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	rlhttp "chainguard.dev/melange/pkg/http"
	"chainguard.dev/melange/pkg/manifest"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/convert/wolfios"
	"chainguard.dev/melange/pkg/util"
	"github.com/pkg/errors"
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
	Logger                 *log.Logger
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
		Logger: log.New(log.Writer(), "convert:apk: ", log.LstdFlags|log.Lmsgprefix),
	}

	var err error
	wolfi := wolfios.New(http.DefaultClient, wolfios.PackageIndex)
	context.WolfiOSPackages, err = wolfi.GetWolfiPackages(ctx)
	if err != nil {
		return context, errors.Wrapf(err, "failed to get packages from wolfi index")
	}

	return context, nil
}

func (c Context) Generate(ctx context.Context, apkBuildURI, pkgName string) error {
	// get the contents of the APKBUILD file
	err := c.getApkBuildFile(ctx, apkBuildURI, pkgName)
	if err != nil {
		return errors.Wrap(err, "getting apk build file")
	}

	// build map of dependencies
	err = c.buildMapOfDependencies(ctx, apkBuildURI, pkgName)
	if err != nil {
		return errors.Wrap(err, "building map of dependencies")
	}

	// reverse map order, so we generate the lowest transitive dependency first
	// this will help to build convert configs in the correct order
	util.ReverseSlice(c.OrderedKeys)

	// loop over map and generate convert config for each
	for i, key := range c.OrderedKeys {

		apkConverter := c.ApkConvertors[key]

		// automatically add a fetch step to the convert config to fetch the source
		err = c.buildFetchStep(ctx, apkConverter)
		if err != nil {
			// lets not error if we can't automatically add the fetch step
			c.Logger.Printf("skipping fetch step for %s", err.Error())
		}

		// maps the APKBUILD values to convert config
		apkConverter.mapconvert()

		// builds the convert environment configuration
		apkConverter.buildEnvironment(c.AdditionalRepositories, c.AdditionalKeyrings)

		err = apkConverter.write(strconv.Itoa(i), c.OutDir)
		if err != nil {
			return errors.Wrap(err, "writing convert config file")
		}
	}

	return nil
}

func (c Context) getApkBuildFile(ctx context.Context, apkbuildURL, packageName string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", apkbuildURL, nil)
	resp, err := c.Client.Do(req)

	if err != nil {
		return errors.Wrapf(err, "getting %s", apkbuildURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non ok http response code: %v", resp.StatusCode)
	}
	apkbuildFile := apkbuild.NewApkbuildFile(packageName, resp.Body)

	parsedApkBuild, err := apkbuild.Parse(apkbuildFile, nil)

	if err != nil {
		return errors.Wrapf(err, "failed to parse apkbuild %s", apkbuildURL)
	}

	c.ApkConvertors[packageName] = ApkConvertor{
		Apkbuild: &parsedApkBuild,
		GeneratedMelangeConfig: &manifest.GeneratedMelangeConfig{
			Logger:               c.Logger,
			GeneratedFromComment: apkbuildURL,
			Package: config.Package{
				Epoch: 0,
			},
		},
	}
	c.OrderedKeys = append(c.OrderedKeys, packageName)
	return nil
}

// recursively add dependencies, and their dependencies to our map
func (c Context) buildMapOfDependencies(ctx context.Context, apkBuildURI, pkgName string) error {
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
		c.Logger.Printf("checking if %s is all ready in wolfi os", dep)
		if c.WolfiOSPackages[dep] {
			c.Logger.Printf("yes it is, skipping...")
			continue
		}

		// if dependency is in the list of packages configured one the CLI to exclude, let's skip
		c.Logger.Printf("checking if %s is in %s", dep, strings.Join(c.ExcludePackages, " "))
		if contains(c.ExcludePackages, dep) {
			c.Logger.Printf("yes it is, skipping...")
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
				c.Logger.Printf("failed to get APKBUILD %s", dependencyApkBuildURI)
				continue
			}

			err = c.buildMapOfDependencies(ctx, dependencyApkBuildURI, dep)
			if err != nil {
				return errors.Wrap(err, "building map of dependencies")
			}
		}
	}
	return nil
}

func (c Context) transitiveDependencyList(convertor ApkConvertor) []string {
	var dependencies []string
	for _, depends := range convertor.Apkbuild.Depends {
		if !util.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	for _, depends := range convertor.Apkbuild.Makedepends {
		if !util.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	for _, depends := range convertor.Apkbuild.DependsDev {
		if !util.Contains(dependencies, depends.Pkgname) {
			dependencies = append(dependencies, depends.Pkgname)
		}
	}
	return dependencies
}

// add pipeline fetch steps, validate checksums and generate mconvert expected sha
func (c Context) buildFetchStep(ctx context.Context, converter ApkConvertor) error {
	apkBuild := converter.Apkbuild

	if len(apkBuild.Source) == 0 {
		c.Logger.Printf("skip adding pipeline for package %s, no source URL found", converter.Pkgname)
		return nil
	}
	if apkBuild.Pkgver == "" {
		return fmt.Errorf("no package version")
	}

	// there can be multiple sources, let's add them all so, it's easier for users to remove from generated files if not needed
	for _, source := range apkBuild.Source {

		location := source.Location

		_, err := url.ParseRequestURI(location)
		if err != nil {
			return errors.Wrapf(err, "parsing URI %s", location)
		}

		req, _ := http.NewRequestWithContext(ctx, "GET", location, nil)
		resp, err := c.Client.Do(req)

		if err != nil {
			return errors.Wrapf(err, "failed getting URI %s", location)
		}
		defer resp.Body.Close()

		failed := false
		if resp.StatusCode != http.StatusOK {
			c.Logger.Printf("non ok http response for URI %s code: %v", location, resp.StatusCode)
			failed = true
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "failed getting URI %s", location)
		}

		var expectedSha string
		if !failed {

			// validate the source we are using matches the correct sha512 in the APKBIULD
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

			// now generate the 256 sha we need for a mconvert config
			if !validated {
				expectedSha = "SHA512 DOES NOT MATCH SOURCE - VALIDATE MANUALLY"
				c.Logger.Printf("source %s expected sha512 do not match!", source.Filename)
			} else {
				h256 := sha256.New()
				h256.Write(b)

				expectedSha = fmt.Sprintf("%x", h256.Sum(nil))
			}

		} else {
			expectedSha = "FIXME - SOURCE URL NOT VALID"
		}

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

	copyright := config.Copyright{
		License: c.Apkbuild.License,
	}
	c.GeneratedMelangeConfig.Package.Copyright = append(c.GeneratedMelangeConfig.Package.Copyright, copyright)

	// triggers
	if c.Apkbuild.Triggers != nil {
		c.GeneratedMelangeConfig.Package.Scriptlets.Trigger.Paths = []string{"FIXME"}
		c.GeneratedMelangeConfig.Package.Scriptlets.Trigger.Script = "FIXME"
	}

	//if c.Apkbuild.Funcs["build"] != nil {
	//	// todo lets check the command and add the correct cmake | make | meson mconvert pipelines
	//	//build := c.Apkbuild.Funcs["build"]
	//}

	//switch c.Apkbuild.BuilderType {
	//
	//case BuilderTypeCMake:
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/configure"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/build"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "cmake/install"})
	//
	//case BuilderTypeMeson:
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/configure"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/compile"})
	//	c.GeneratedMelangeConfig.Pipeline = append(c.GeneratedMelangeConfig.Pipeline, config.Pipeline{Uses: "meson/install"})
	//
	//case BuilderTypeMake:
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
		//parts := strings.Split(subPackage.Subpkgname, "-")

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
		Contents: struct {
			Repositories []string `yaml:"repositories,omitempty"`
			Keyring      []string `yaml:"keyring,omitempty"`
			Packages     []string `yaml:"packages,omitempty"`
		}(struct {
			Repositories []string
			Keyring      []string
			Packages     []string
		}{
			Packages: []string{
				"busybox",
				"ca-certificates-bundle",
				"build-base",
				"automake",
				"autoconf",
			},
		}),
	}

	env.Contents.Repositories = append(env.Contents.Repositories, additionalRepositories...)
	env.Contents.Keyring = append(env.Contents.Keyring, additionalKeyrings...)
	for _, makedepend := range c.Apkbuild.Makedepends {
		env.Contents.Packages = append(env.Contents.Packages, makedepend.Pkgname)
	}

	for _, dependsDev := range c.Apkbuild.DependsDev {
		d := dependsDev.Pkgname
		if !strings.HasSuffix(d, "-dev") {
			d = d + "-dev"
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

func (c ApkConvertor) write(orderNumber, outdir string) error {

	actual, err := yaml.Marshal(&c.GeneratedMelangeConfig)
	if err != nil {
		return errors.Wrapf(err, "marshalling mconvert configuration")
	}

	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		err = os.MkdirAll(outdir, os.ModePerm)
		if err != nil {
			return errors.Wrapf(err, "creating output directory %s", outdir)
		}
	}

	// write the mconvert config, prefix with our guessed order along with zero to help users easily rename / reorder generated files
	mconvertFile := filepath.Join(outdir, orderNumber+"0-"+c.Apkbuild.Pkgname+".yaml")
	f, err := os.Create(mconvertFile)
	if err != nil {
		return errors.Wrapf(err, "creating file %s", mconvertFile)
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("# Generated from %s\n", c.GeneratedMelangeConfig.GeneratedFromComment))
	if err != nil {
		return errors.Wrapf(err, "creating writing to file %s", mconvertFile)
	}

	_, err = f.WriteString(string(actual))
	if err != nil {
		return errors.Wrapf(err, "creating writing to file %s", mconvertFile)
	}
	return nil
}
