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

package cache

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/util"
)

// CacheConfig contains the configuration data for a bump
// renovator.
type CacheConfig struct {
	CacheDir       string
	packageName    string
	packageVersion string
}

// Option sets a config option on a CacheConfig.
type Option func(cfg *CacheConfig) error

// WithCacheDir sets the desired target directory for cache
// artifacts to be fetched to.
func WithCacheDir(cacheDir string) Option {
	return func(cfg *CacheConfig) error {
		cfg.CacheDir = cacheDir
		return nil
	}
}

// New returns a renovator which fetches cache dependencies.
func New(opts ...Option) renovate.Renovator {
	cfg := CacheConfig{}

	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return func(context.Context, *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	if cfg.CacheDir == "" {
		return func(context.Context, *renovate.RenovationContext) error {
			return fmt.Errorf("cache directory is not set")
		}
	}

	return func(ctx context.Context, rc *renovate.RenovationContext) error {
		// Find the package.name and package.version nodes.
		packageNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "package")
		if err != nil {
			return err
		}

		nameNode, err := renovate.NodeFromMapping(packageNode, "name")
		if err != nil {
			return err
		}
		cfg.packageName = nameNode.Value

		versionNode, err := renovate.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}
		cfg.packageVersion = versionNode.Value

		log.Printf("fetching artifacts relating to %s-%s", cfg.packageName, cfg.packageVersion)

		// Find our main pipeline YAML node.
		pipelineNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "pipeline")
		if err != nil {
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := visitFetch(ctx, fetchNode, cfg); err != nil {
				return err
			}
		}

		return nil
	}
}

// visitFetch takes a "fetch" pipeline node
func visitFetch(ctx context.Context, node *yaml.Node, cfg CacheConfig) error {
	withNode, err := renovate.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	uriNode, err := renovate.NodeFromMapping(withNode, "uri")
	if err != nil {
		return err
	}

	log.Printf("processing fetch node:")

	// Fetch the new sources.
	evaluatedUri := strings.ReplaceAll(uriNode.Value, "${{package.version}}", cfg.packageVersion)
	evaluatedUri = strings.ReplaceAll(evaluatedUri, "${{package.name}}", cfg.packageName)
	log.Printf("  uri: %s", uriNode.Value)
	log.Printf("  evaluated: %s", evaluatedUri)

	downloadedFile, err := util.DownloadFile(ctx, evaluatedUri)
	if err != nil {
		return err
	}
	defer os.Remove(downloadedFile)
	log.Printf("  fetched-as: %s", downloadedFile)

	// Calculate SHA2-256 and SHA2-512 hashes.
	fileSHA256, err := util.HashFile(downloadedFile, sha256.New())
	if err != nil {
		return err
	}
	log.Printf("  actual-sha256: %s", fileSHA256)

	fileSHA512, err := util.HashFile(downloadedFile, sha512.New())
	if err != nil {
		return err
	}
	log.Printf("  actual-sha512: %s", fileSHA512)

	// Update expected hash nodes.
	nodeSHA256, err := renovate.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		if err := addFileToCache(ctx, cfg, downloadedFile, fileSHA256, nodeSHA256.Value, "sha256"); err != nil {
			return err
		}
	}

	nodeSHA512, err := renovate.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		if err := addFileToCache(ctx, cfg, downloadedFile, fileSHA512, nodeSHA512.Value, "sha512"); err != nil {
			return err
		}
	}

	return nil
}

// addFileToCache adds a file to the CacheDir.
func addFileToCache(ctx context.Context, cfg CacheConfig, downloadedFile string, compHash string, cfgHash string, hashFamily string) error {
	if compHash != cfgHash {
		return fmt.Errorf("%s mismatch: %s != %s", hashFamily, compHash, cfgHash)
	}

	filename := fmt.Sprintf("%s:%s", hashFamily, cfgHash)
	destinationPath := path.Join(cfg.CacheDir, filename)

	var destinationFile io.WriteCloser
	if strings.HasPrefix(cfg.CacheDir, "gs://") {
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(cfg.CacheDir, "gs://"), "/")
		client, err := storage.NewClient(ctx)
		if err != nil {
			return err
		}
		destinationFile = client.Bucket(bucket).Object(path.Join(prefix, filename)).NewWriter(ctx)
	} else if strings.HasPrefix(cfg.CacheDir, "s3://") {
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(cfg.CacheDir, "s3://"), "/")
		sess := session.Must(session.NewSession())
		uploader := s3manager.NewUploader(sess)
		sourceFile, err := os.Open(downloadedFile)
		if err != nil {
			return err
		}
		defer sourceFile.Close()
		_, err = uploader.Upload(&s3manager.UploadInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(path.Join(prefix, filename)),
			Body:   sourceFile,
		})
		if err != nil {
			return err
		} else {
			log.Printf("  wrote: %s", destinationPath)
			return nil
		}
	} else {
		var err error
		destinationFile, err = os.Create(destinationPath)
		if err != nil {
			return err
		}
	}
	defer destinationFile.Close()

	sourceFile, err := os.Open(downloadedFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	log.Printf("  wrote: %s", destinationPath)

	return nil
}
