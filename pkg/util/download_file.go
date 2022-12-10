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

package util

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// DownloadFile downloads a file and returns a path to it in temporary storage.
func DownloadFile(uri string) (string, error) {
	targetFile, err := os.CreateTemp("", "melange-update-*")
	if err != nil {
		return "", err
	}
	defer targetFile.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// delete the referer header else redirects with sourceforge do not work well.  See https://stackoverflow.com/questions/67203383/downloading-from-sourceforge-wait-and-redirect
			req.Header.Del("Referer")
			return nil
		},
	}

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %s when fetching %s", resp.Status, filepath.Base(uri))
	}

	if _, err := io.Copy(targetFile, resp.Body); err != nil {
		return "", err
	}

	return targetFile.Name(), nil
}

// HashFile calculates the hash for a file and returns it as a hex string.
func HashFile(downloadedFile string, digest hash.Hash) (string, error) {
	hashedFile, err := os.Open(downloadedFile)
	if err != nil {
		return "", err
	}
	defer hashedFile.Close()

	if _, err := io.Copy(digest, hashedFile); err != nil {
		return "", err
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}
