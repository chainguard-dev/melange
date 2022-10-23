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

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
)

func Publish() *cobra.Command {
	var packagesDir string
	cmd := &cobra.Command{
		Use:     "publish [BUCKET]",
		Short:   "Publish a packages directory to a remote location",
		Example: "melange publish gs://my-bucket/path/to/packages",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dst := args[0]

			if !strings.Contains(dst, "://") {
				return errors.New("malformed destination")
			}
			bp := dst[strings.Index(dst, "://")+3:]
			bucket, prefix, _ := strings.Cut(bp, "/")
			scheme := dst[:strings.Index(dst, "://")]

			b, err := blob.OpenBucket(ctx, fmt.Sprintf("%s://%s", scheme, bucket))
			if err != nil {
				return err
			}
			if prefix != "" {
				prefix = path.Clean(prefix) + "/"
				b = blob.PrefixedBucket(b, prefix)
			}
			defer b.Close()

			return filepath.Walk(packagesDir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return nil // Don't upload non-files.
				}

				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer func() { err = f.Close() }()

				w, err := b.NewWriter(ctx, path, &blob.WriterOptions{})
				if err != nil {
					return err
				}
				if _, err = io.Copy(w, f); err != nil {
					return err
				}
				if err := w.Close(); err != nil {
					return err
				}
				log.Println("wrote", filepath.Join(dst, path))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&packagesDir, "packages-dir", "./packages", "directory where packages will be output")
	return cmd
}
