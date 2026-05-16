// Copyright 2026 Chainguard, Inc.
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

package docker

import (
	"strings"
	"testing"
)

// TestUniqueImageTag_DistinctOverManyCalls guards the core invariant of the
// shared-tag race fix: two consecutive calls to uniqueImageTag must never
// produce the same string, even at high volume. A regression that replaces the
// random suffix with a constant (or with something time-based and
// insufficiently granular) would resurface the "AlreadyExists" race at
// concurrent scale, which is what this whole helper exists to prevent.
func TestUniqueImageTag_DistinctOverManyCalls(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := range n {
		tag, err := uniqueImageTag()
		if err != nil {
			t.Fatalf("uniqueImageTag failed at call %d: %v", i, err)
		}
		if _, dup := seen[tag]; dup {
			t.Fatalf("collision after %d calls: %s", len(seen), tag)
		}
		seen[tag] = struct{}{}
	}
}

// TestUniqueImageTag_ShapeAndPrefix pins the format so a downstream parser or
// log scraper can rely on it. The prefix must remain "melange:" and the suffix
// must be hex characters (no extra padding, separators, or stray bytes).
func TestUniqueImageTag_ShapeAndPrefix(t *testing.T) {
	tag, err := uniqueImageTag()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tag, "melange:") {
		t.Errorf("tag %q does not start with %q", tag, "melange:")
	}
	body := strings.TrimPrefix(tag, "melange:")
	// Body is "<pid>-<16 hex chars>".
	dash := strings.Index(body, "-")
	if dash <= 0 {
		t.Fatalf("tag body %q missing pid-suffix separator", body)
	}
	pid, suffix := body[:dash], body[dash+1:]
	if pid == "" {
		t.Errorf("empty pid segment in %q", tag)
	}
	for _, r := range pid {
		if r < '0' || r > '9' {
			t.Errorf("non-digit %q in pid segment of %q", r, tag)
		}
	}
	if len(suffix) != 16 {
		t.Errorf("hex suffix wrong length: got %d, want 16 (in %q)", len(suffix), tag)
	}
	for _, r := range suffix {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			t.Errorf("non-hex character %q in suffix of %q", r, tag)
		}
	}
}
