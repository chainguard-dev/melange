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

package types

// DuplicateFileInfo represents information about a set of duplicate files
type DuplicateFileInfo struct {
	Basename    string   `json:"basename"`
	Count       int      `json:"count"`
	SizeBytes   int64    `json:"size_bytes"`
	Size        string   `json:"size"`
	WastedBytes int64    `json:"wasted_bytes"`
	WastedSize  string   `json:"wasted_size"`
	Paths       []string `json:"paths"`
}

// DuplicateFilesDetails contains structured information about duplicate files
type DuplicateFilesDetails struct {
	TotalDuplicateSets int                  `json:"total_duplicate_sets"`
	TotalWastedBytes   int64                `json:"total_wasted_bytes"`
	TotalWastedSize    string               `json:"total_wasted_size"`
	Duplicates         []*DuplicateFileInfo `json:"duplicates"`
}

// FilePermissionInfo represents a file with special permissions
type FilePermissionInfo struct {
	Path        string   `json:"path"`
	Mode        string   `json:"mode"`
	Permissions []string `json:"permissions,omitempty"` // e.g., ["setuid", "setgid"]
}

// SpecialPermissionsDetails contains files with special permissions
type SpecialPermissionsDetails struct {
	Files []FilePermissionInfo `json:"files"`
}

// WorldWriteableDetails contains files that are world-writeable
type WorldWriteableDetails struct {
	Files []FilePermissionInfo `json:"files"`
}

// UsrMergeDetails contains paths that violate usrmerge
type UsrMergeDetails struct {
	Paths []string `json:"paths"`
}

// BinaryArchDetails contains binaries with architecture info
type BinaryArchDetails struct {
	Binaries []BinaryArchInfo `json:"binaries"`
}

// BinaryArchInfo represents a binary with its architecture
type BinaryArchInfo struct {
	Path string `json:"path"`
	Arch string `json:"arch"`
}

// UnsupportedArchDetails contains files with unsupported arch references
type UnsupportedArchDetails struct {
	Files []UnsupportedArchInfo `json:"files"`
}

// UnsupportedArchInfo represents a file with unsupported architecture reference
type UnsupportedArchInfo struct {
	Path string `json:"path"`
	Arch string `json:"arch"`
}

// PythonMultipleDetails contains info about multiple Python packages
type PythonMultipleDetails struct {
	Count    int      `json:"count"`
	Packages []string `json:"packages"`
}

// UnstrippedBinaryDetails contains info about unstripped binaries
type UnstrippedBinaryDetails struct {
	Binaries []string `json:"binaries"`
}

// PathListDetails is a generic structure for linters that just report paths
type PathListDetails struct {
	Paths []string `json:"paths"`
}

// NonLinuxReference represents a file with non-Linux platform references
type NonLinuxReference struct {
	Path     string `json:"path"`
	Platform string `json:"platform"` // e.g., "macos", "windows"
}

// NonLinuxDetails contains files with non-Linux platform references
type NonLinuxDetails struct {
	References []NonLinuxReference `json:"references"`
}

// StructuredError is an error that carries structured details for JSON serialization
type StructuredError struct {
	Message string
	Details any
}

// Error returns the error message
func (e *StructuredError) Error() string {
	return e.Message
}

// NewStructuredError creates a new error with structured details
func NewStructuredError(message string, details any) error {
	return &StructuredError{
		Message: message,
		Details: details,
	}
}

// LinterFinding represents a single finding from a linter
type LinterFinding struct {
	Message string `json:"message"`
	Explain string `json:"explain,omitempty"`
	Details any    `json:"details,omitempty"` // Structured data specific to the linter
}

// PackageLintResults contains all linter findings for a package
type PackageLintResults struct {
	PackageName string                      `json:"package_name"`
	Findings    map[string][]*LinterFinding `json:"findings"` // map of linter name -> findings
}
