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

// Package tarball provides compatibility aliases for the internal tarball package.
// Deprecated: These types and functions are deprecated and will be removed in a future version.
// External packages should not depend on melange's tarball implementation.
package tarball

import (
	"chainguard.dev/melange/internal/tarball"
)

// Context is a compatibility alias for the internal type.
// Deprecated: This type will be removed in a future version.
type Context = tarball.Context

// Option is a compatibility alias for the internal type.
// Deprecated: This type will be removed in a future version.
type Option = tarball.Option

// NewContext is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func NewContext(opts ...Option) (*Context, error) {
	return tarball.NewContext(opts...)
}

// WithOverrideUIDGID is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithOverrideUIDGID(uid, gid int) Option {
	return tarball.WithOverrideUIDGID(uid, gid)
}

// WithOverrideUname is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithOverrideUname(uname string) Option {
	return tarball.WithOverrideUname(uname)
}

// WithOverrideGname is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithOverrideGname(gname string) Option {
	return tarball.WithOverrideGname(gname)
}

// WithSkipClose is a compatibility wrapper for the internal function.
// Deprecated: This function will be removed in a future version.
func WithSkipClose(skipClose bool) Option {
	return tarball.WithSkipClose(skipClose)
}
