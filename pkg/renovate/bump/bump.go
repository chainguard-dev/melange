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

// Package bump provides compatibility aliases for the internal renovate/bump package.
// Deprecated: These types and functions are deprecated and will be removed in a future version.
// External packages should not depend on melange's bump implementation.
package bump

import (
	"context"

	"chainguard.dev/melange/internal/renovate"
	"chainguard.dev/melange/internal/renovate/bump"
)

// Option is a compatibility alias for the internal type.
// Deprecated: This type will be removed in a future version.
type Option = bump.Option

// New is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func New(ctx context.Context, opts ...Option) renovate.Renovator {
	return bump.New(ctx, opts...)
}

// WithTargetVersion is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithTargetVersion(v string) Option {
	return bump.WithTargetVersion(v)
}

// WithExpectedCommit is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithExpectedCommit(c string) Option {
	return bump.WithExpectedCommit(c)
}
