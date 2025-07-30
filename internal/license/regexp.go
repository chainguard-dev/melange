// Copyright 2014-2021 Ben Balter and Licensee contributors
// Copyright 2025 Chainguard, Inc.
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
//
// ----
//
// Portions of this file were originally licensed under the MIT License.
// Copyright (c) 2014-2021 Ben Balter and Licensee contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// The following code has been adjusted from Ruby to Go from the Licensee project.

package license

import "regexp"

var (
	preferredExt      = []string{".md", ".markdown", ".txt", ".html"}
	ignoredExt        = []string{".xml", ".go", ".gemspec", ".spdx", ".header"}
	preferredExtRegex = regexp.MustCompile(`\.(?:` + regexp.QuoteMeta(preferredExt[0]) + `|` + regexp.QuoteMeta(preferredExt[1]) + `|` + regexp.QuoteMeta(preferredExt[2]) + `|` + regexp.QuoteMeta(preferredExt[3]) + `)$`)
	anyExtRegex       = regexp.MustCompile(`(\.[^./]+$)`)
	licenseRegex      = regexp.MustCompile(`(?i)(un)?licen[sc]e`)
	copyingRegex      = regexp.MustCompile(`(?i)copy(ing|right)`)
	oflRegex          = regexp.MustCompile(`(?i)ofl`)
	patentsRegex      = regexp.MustCompile(`(?i)patents`)
	filenameRegexes   = map[*regexp.Regexp]float64{
		regexp.MustCompile(`(?i)^` + licenseRegex.String() + `$`):                                          1.00, // LICENSE
		regexp.MustCompile(`(?i)^` + licenseRegex.String() + preferredExtRegex.String() + `$`):             0.95, // LICENSE.md
		regexp.MustCompile(`(?i)^` + copyingRegex.String() + `$`):                                          0.90, // COPYING
		regexp.MustCompile(`(?i)^` + copyingRegex.String() + preferredExtRegex.String() + `$`):             0.85, // COPYING.md
		regexp.MustCompile(`(?i)^` + licenseRegex.String() + anyExtRegex.String() + `$`):                   0.80, // LICENSE.textile
		regexp.MustCompile(`(?i)^` + copyingRegex.String() + anyExtRegex.String() + `$`):                   0.75, // COPYING.textile
		regexp.MustCompile(`(?i)^` + licenseRegex.String() + `[-_][^.]*` + anyExtRegex.String() + `?$`):    0.70, // LICENSE-MIT
		regexp.MustCompile(`(?i)^` + copyingRegex.String() + `[-_][^.]*` + anyExtRegex.String() + `?$`):    0.65, // COPYING-MIT
		regexp.MustCompile(`(?i)^\w+[-_]` + licenseRegex.String() + `[^.]*` + anyExtRegex.String() + `?$`): 0.60, // MIT-LICENSE-MIT
		regexp.MustCompile(`(?i)^\w+[-_]` + copyingRegex.String() + `[^.]*` + anyExtRegex.String() + `?$`): 0.55, // MIT-COPYING
		regexp.MustCompile(`(?i)^` + oflRegex.String() + preferredExtRegex.String()):                       0.50, // OFL.md
		regexp.MustCompile(`(?i)^` + oflRegex.String() + anyExtRegex.String()):                             0.45, // OFL.textile
		regexp.MustCompile(`(?i)^` + oflRegex.String() + `$`):                                              0.40, // OFL
		regexp.MustCompile(`(?i)^` + patentsRegex.String() + `$`):                                          0.35, // PATENTS
		regexp.MustCompile(`(?i)^` + patentsRegex.String() + anyExtRegex.String() + `$`):                   0.30, // PATENTS.txt
	}
)
