// Copyright 2023 Chainguard, Inc.
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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/sca"
)

type scanConfig struct {
	key      string
	repo     string
	pkg      string
	archs    []string
	diff     bool
	comments bool

	purlNamespace string
}

func scan() *cobra.Command {
	sc := scanConfig{}

	cmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan an existing APK to regenerate .PKGINFO",
		Example: `melange scan bash.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return scanCmd(cmd.Context(), args[0], &sc)
		},
	}

	// These are oddly named but they match what we do in other tools, which makes this much easier to copy/paste.
	cmd.Flags().StringVarP(&sc.key, "keyring-append", "k", "local-melange.rsa.pub", "path to key to include in the build environment keyring")
	cmd.Flags().StringVarP(&sc.repo, "repository-append", "r", "./packages", "path to repository to include in the build environment")
	cmd.Flags().StringVarP(&sc.pkg, "package", "p", "", "which package's .PKGINFO to print (if there are subpackages)")

	cmd.Flags().StringSliceVar(&sc.archs, "arch", []string{}, "architectures to scan (default is x86_64)")
	cmd.Flags().BoolVar(&sc.diff, "diff", false, "show diff output")
	cmd.Flags().BoolVar(&sc.comments, "comments", false, "include comments in .PKGINFO diff")

	cmd.Flags().StringVar(&sc.purlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")

	return cmd
}

// TODO: It would be cool if there was a way this could take just a directory.
func scanCmd(ctx context.Context, file string, sc *scanConfig) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "scan")
	defer span.End()

	log := clog.FromContext(ctx)

	sawDiff := false

	archs := sc.archs
	if len(archs) == 0 {
		archs = []string{"x86_64"}
	}

	cfg, err := config.ParseConfiguration(ctx, file)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	for _, arch := range archs {
		exps := map[string]*expandapk.APKExpanded{}

		pkg := cfg.Package

		u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", sc.repo, arch, pkg.Name, pkg.Version, pkg.Epoch)

		var r io.Reader
		if strings.HasPrefix(u, "http") {
			// #nosec G107 - URL is constructed from trusted configuration values
			resp, err := http.Get(u)
			if err != nil {
				return fmt.Errorf("get %s: %w", u, err)
			}
			defer resp.Body.Close()
			r = resp.Body
		} else {
			f, err := os.Open(u) // #nosec G304 - User-specified APK or config file for scanning
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		exp, err := expandapk.ExpandApk(ctx, r, "")
		if err != nil {
			return err
		}
		defer exp.Close()

		exps[pkg.Name] = exp

		f, err := exp.ControlFS.Open(".PKGINFO")
		if err != nil {
			return fmt.Errorf("opening .PKGINFO in %s: %w", exp.ControlFile, err)
		}
		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		info, err := parsePkgInfo(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("parsing .PKGINFO: %w", err)
		}

		pkg.Commit = info.commit

		installedSize, err := strconv.ParseInt(info.size, 10, 64)
		if err != nil {
			return err
		}

		dir, err := os.MkdirTemp("", info.pkgname)
		if err != nil {
			return fmt.Errorf("mkdirtemp: %w", err)
		}
		defer os.RemoveAll(dir)

		bb := &build.Build{
			WorkspaceDir:    dir,
			SourceDateEpoch: time.Unix(0, 0),
			Configuration:   cfg,
			Namespace:       sc.purlNamespace,
		}

		pb := build.PackageBuild{
			Build:         bb,
			Origin:        &pkg,
			PackageName:   pkg.Name,
			OriginName:    pkg.Name,
			Dependencies:  pkg.Dependencies,
			Options:       pkg.Options,
			Scriptlets:    pkg.Scriptlets,
			Description:   pkg.Description,
			URL:           pkg.URL,
			Commit:        pkg.Commit,
			InstalledSize: installedSize,
			DataHash:      info.datahash,
			Arch:          info.arch,
		}

		if info.builddate != "" {
			sec, err := strconv.ParseInt(info.builddate, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
			}
			pb.Build.SourceDateEpoch = time.Unix(sec, 0)
		}

		subpkgs := map[string]build.PackageBuild{}
		controls := map[string][]byte{}
		infos := map[string]*pkginfo{}

		for _, subpkg := range cfg.Subpackages {
			u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", sc.repo, arch, subpkg.Name, pkg.Version, pkg.Epoch)

			var r io.Reader
			if strings.HasPrefix(u, "http") {
				// #nosec G107 - URL is constructed from trusted configuration values
				resp, err := http.Get(u)
				if err != nil {
					return fmt.Errorf("get %s: %w", u, err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					log.Errorf("Get %s: %d", u, resp.StatusCode)
					continue
				}
				r = resp.Body
			} else {
				f, err := os.Open(u) // #nosec G304 - User-specified APK or config file for scanning
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}

			exp, err := expandapk.ExpandApk(ctx, r, "")
			if err != nil {
				return err
			}
			defer exp.Close()

			exps[subpkg.Name] = exp

			f, err := exp.ControlFS.Open(".PKGINFO")
			if err != nil {
				return fmt.Errorf("opening .PKGINFO in %s: %w", exp.ControlFile, err)
			}
			defer f.Close()

			b, err := io.ReadAll(f)
			if err != nil {
				return err
			}
			info, err := parsePkgInfo(bytes.NewReader(b))
			if err != nil {
				return fmt.Errorf("parsing .PKGINFO: %w", err)
			}

			infos[subpkg.Name] = info
			controls[subpkg.Name] = b

			subpkg.Commit = info.commit

			installedSize, err := strconv.ParseInt(info.size, 10, 64)
			if err != nil {
				return err
			}

			pb := build.PackageBuild{
				Build:         bb,
				Origin:        &pkg,
				PackageName:   subpkg.Name,
				OriginName:    pkg.Name,
				Dependencies:  subpkg.Dependencies,
				Options:       subpkg.Options,
				Scriptlets:    subpkg.Scriptlets,
				Description:   subpkg.Description,
				URL:           subpkg.URL,
				Commit:        subpkg.Commit,
				InstalledSize: installedSize,
				DataHash:      info.datahash,
				Arch:          info.arch,
			}

			subpkgs[subpkg.Name] = pb

			if info.builddate != "" {
				sec, err := strconv.ParseInt(info.builddate, 10, 64)
				if err != nil {
					return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
				}
				pb.Build.SourceDateEpoch = time.Unix(sec, 0)
			}
		}

		for _, subpkg := range cfg.Subpackages {
			pb, ok := subpkgs[subpkg.Name]
			if !ok {
				continue
			}
			info := infos[subpkg.Name]

			hdl := &scaImpl{
				pb:   &pb,
				exps: exps,
			}

			if err := pb.GenerateDependencies(ctx, hdl); err != nil {
				return err
			}

			var buf bytes.Buffer
			if err := pb.GenerateControlData(&buf); err != nil {
				return fmt.Errorf("unable to process control template: %w", err)
			}

			generated := buf.Bytes()

			if sc.diff {
				b := controls[subpkg.Name]
				old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)

				diff := Diff(old, b, file, generated, sc.comments)
				if diff != nil {
					sawDiff = true
					if _, err := os.Stdout.Write(diff); err != nil {
						return fmt.Errorf("failed to write diff: %w", err)
					}
				}
			} else if sc.pkg == "" || sc.pkg == subpkg.Name {
				if _, err := os.Stdout.Write(generated); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}
		}

		hdl := &scaImpl{
			pb:   &pb,
			exps: exps,
		}

		if err := pb.GenerateDependencies(ctx, hdl); err != nil {
			return err
		}

		var buf bytes.Buffer
		if err := pb.GenerateControlData(&buf); err != nil {
			return fmt.Errorf("unable to process control template: %w", err)
		}

		generated := buf.Bytes()

		if sc.diff {
			old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)
			diff := Diff(old, b, file, generated, sc.comments)
			if diff != nil {
				sawDiff = true
				if _, err := os.Stdout.Write(diff); err != nil {
					return fmt.Errorf("failed to write diff: %w", err)
				}
			}
		} else if sc.pkg == "" || sc.pkg == pkg.Name {
			if _, err := os.Stdout.Write(generated); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}
	}

	if sawDiff {
		return fmt.Errorf("saw diff for %s", file)
	}

	return nil
}

type pkginfo struct {
	pkgname   string
	pkgver    string
	size      string
	arch      string
	origin    string
	pkgdesc   string
	url       string
	commit    string
	builddate string
	license   string
	triggers  string
	datahash  string
}

// TODO: import "gopkg.in/ini.v1"
func parsePkgInfo(in io.Reader) (*pkginfo, error) {
	scanner := bufio.NewScanner(in)

	pkg := pkginfo{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)

		switch before {
		case "pkgname":
			pkg.pkgname = after
		case "pkgver":
			pkg.pkgver = after
		case "arch":
			pkg.arch = after
		case "size":
			pkg.size = after
		case "origin":
			pkg.origin = after
		case "pkgdesc":
			pkg.pkgdesc = after
		case "url":
			pkg.url = after
		case "commit":
			pkg.commit = after
		case "builddate":
			pkg.builddate = after
		case "license":
			pkg.license = after
		case "triggers":
			pkg.triggers = after
		case "datahash":
			pkg.datahash = after
		}
	}

	return &pkg, scanner.Err()
}

// Based on pkg/build/sca_interface but swapping out dirfs for tarfs
type scaImpl struct {
	pb   *build.PackageBuild
	exps map[string]*expandapk.APKExpanded
}

func (s *scaImpl) PackageName() string {
	return s.pb.PackageName
}

func (s *scaImpl) RelativeNames() []string {
	targets := []string{s.pb.Origin.Name}

	for _, target := range s.pb.Build.Configuration.Subpackages {
		targets = append(targets, target.Name)
	}

	return targets
}

func (s *scaImpl) Version() string {
	return fmt.Sprintf("%s-r%d", s.pb.Origin.Version, s.pb.Origin.Epoch)
}

func (s *scaImpl) FilesystemForRelative(pkgName string) (sca.SCAFS, error) {
	exp, ok := s.exps[pkgName]
	if !ok {
		return nil, fmt.Errorf("no package %q", pkgName)
	}

	return exp.TarFS, nil
}

func (s *scaImpl) Filesystem() (sca.SCAFS, error) {
	return s.FilesystemForRelative(s.PackageName())
}

func (s *scaImpl) Options() config.PackageOption {
	if s.pb.Options == nil {
		return config.PackageOption{}
	}
	return *s.pb.Options
}

func (s *scaImpl) BaseDependencies() config.Dependencies {
	return s.pb.Dependencies
}

func (s *scaImpl) InstalledPackages() map[string]string {
	pkgVersionMap := make(map[string]string)

	for _, fullpkg := range s.pb.Build.Configuration.Environment.Contents.Packages {
		pkg, version, _ := strings.Cut(fullpkg, "=")
		pkgVersionMap[pkg] = version
	}

	// We also include the packages being built.
	for _, pkg := range s.RelativeNames() {
		pkgVersionMap[pkg] = s.Version()
	}

	return pkgVersionMap
}

func (s *scaImpl) PkgResolver() *apk.PkgResolver {
	if s.pb.Build == nil || s.pb.Build.PkgResolver == nil {
		return nil
	}
	return s.pb.Build.PkgResolver
}

func isComment(b string) bool {
	return strings.HasPrefix(b, "#")
}

// From src/internal/diff/diff.go

// A pair is a pair of values tracked for both the x and y side of a diff.
// It is typically a pair of line indexes.
type pair struct{ x, y int }

// Diff returns an anchored diff of the two texts old and new
// in the “unified diff” format. If old and new are identical,
// Diff returns a nil slice (no output).
//
// Unix diff implementations typically look for a diff with
// the smallest number of lines inserted and removed,
// which can in the worst case take time quadratic in the
// number of lines in the texts. As a result, many implementations
// either can be made to run for a long time or cut off the search
// after a predetermined amount of work.
//
// In contrast, this implementation looks for a diff with the
// smallest number of “unique” lines inserted and removed,
// where unique means a line that appears just once in both old and new.
// We call this an “anchored diff” because the unique lines anchor
// the chosen matching regions. An anchored diff is usually clearer
// than a standard diff, because the algorithm does not try to
// reuse unrelated blank lines or closing braces.
// The algorithm also guarantees to run in O(n log n) time
// instead of the standard O(n²) time.
//
// Some systems call this approach a “patience diff,” named for
// the “patience sorting” algorithm, itself named for a solitaire card game.
// We avoid that name for two reasons. First, the name has been used
// for a few different variants of the algorithm, so it is imprecise.
// Second, the name is frequently interpreted as meaning that you have
// to wait longer (to be patient) for the diff, meaning that it is a slower algorithm,
// when in fact the algorithm is faster than the standard one.
func Diff(oldName string, old []byte, newName string, new []byte, comments bool) []byte {
	if bytes.Equal(old, new) {
		return nil
	}

	x := lines(old)
	y := lines(new)

	if !comments {
		x = slices.DeleteFunc(x, isComment)
		y = slices.DeleteFunc(y, isComment)

		if slices.Equal(x, y) {
			return nil
		}
	}

	// Print diff header.
	var out bytes.Buffer
	fmt.Fprintf(&out, "diff %s %s\n", oldName, newName)
	fmt.Fprintf(&out, "--- %s\n", oldName)
	fmt.Fprintf(&out, "+++ %s\n", newName)

	// Loop over matches to consider,
	// expanding each match to include surrounding lines,
	// and then printing diff chunks.
	// To avoid setup/teardown cases outside the loop,
	// tgs returns a leading {0,0} and trailing {len(x), len(y)} pair
	// in the sequence of matches.
	var (
		done  pair     // printed up to x[:done.x] and y[:done.y]
		chunk pair     // start lines of current chunk
		count pair     // number of lines from each side in current chunk
		ctext []string // lines for current chunk
	)
	for _, m := range tgs(x, y) {
		if m.x < done.x {
			// Already handled scanning forward from earlier match.
			continue
		}

		// Expand matching lines as far possible,
		// establishing that x[start.x:end.x] == y[start.y:end.y].
		// Note that on the first (or last) iteration we may (or definitely do)
		// have an empty match: start.x==end.x and start.y==end.y.
		start := m
		for start.x > done.x && start.y > done.y && x[start.x-1] == y[start.y-1] {
			start.x--
			start.y--
		}
		end := m
		for end.x < len(x) && end.y < len(y) && x[end.x] == y[end.y] {
			end.x++
			end.y++
		}

		// Emit the mismatched lines before start into this chunk.
		// (No effect on first sentinel iteration, when start = {0,0}.)
		for _, s := range x[done.x:start.x] {
			ctext = append(ctext, "-"+s)
			count.x++
		}
		for _, s := range y[done.y:start.y] {
			ctext = append(ctext, "+"+s)
			count.y++
		}

		// If we're not at EOF and have too few common lines,
		// the chunk includes all the common lines and continues.
		const C = 3 // number of context lines
		if (end.x < len(x) || end.y < len(y)) &&
			(end.x-start.x < C || (len(ctext) > 0 && end.x-start.x < 2*C)) {
			for _, s := range x[start.x:end.x] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}
			done = end
			continue
		}

		// End chunk with common lines for context.
		if len(ctext) > 0 {
			n := min(end.x-start.x, C)
			for _, s := range x[start.x : start.x+n] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}

			// Format and emit chunk.
			// Convert line numbers to 1-indexed.
			// Special case: empty file shows up as 0,0 not 1,0.
			if count.x > 0 {
				chunk.x++
			}
			if count.y > 0 {
				chunk.y++
			}
			fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", chunk.x, count.x, chunk.y, count.y)
			for _, s := range ctext {
				out.WriteString(s)
			}
			count.x = 0
			count.y = 0
			ctext = ctext[:0]
		}

		// If we reached EOF, we're done.
		if end.x >= len(x) && end.y >= len(y) {
			break
		}

		// Otherwise start a new chunk.
		chunk = pair{end.x - C, end.y - C}
		for _, s := range x[chunk.x:end.x] {
			ctext = append(ctext, " "+s)
			count.x++
			count.y++
		}
		done = end
	}

	return out.Bytes()
}

// lines returns the lines in the file x, including newlines.
// If the file does not end in a newline, one is supplied
// along with a warning about the missing newline.
func lines(x []byte) []string {
	l := strings.SplitAfter(string(x), "\n")
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	} else {
		// Treat last line as having a message about the missing newline attached,
		// using the same text as BSD/GNU diff (including the leading backslash).
		l[len(l)-1] += "\n\\ No newline at end of file\n"
	}
	return l
}

// tgs returns the pairs of indexes of the longest common subsequence
// of unique lines in x and y, where a unique line is one that appears
// once in x and once in y.
//
// The longest common subsequence algorithm is as described in
// Thomas G. Szymanski, “A Special Case of the Maximal Common
// Subsequence Problem,” Princeton TR #170 (January 1975),
// available at https://research.swtch.com/tgs170.pdf.
func tgs(x, y []string) []pair {
	// Count the number of times each string appears in a and b.
	// We only care about 0, 1, many, counted as 0, -1, -2
	// for the x side and 0, -4, -8 for the y side.
	// Using negative numbers now lets us distinguish positive line numbers later.
	m := make(map[string]int)
	for _, s := range x {
		if c := m[s]; c > -2 {
			m[s] = c - 1
		}
	}
	for _, s := range y {
		if c := m[s]; c > -8 {
			m[s] = c - 4
		}
	}

	// Now unique strings can be identified by m[s] = -1+-4.
	//
	// Gather the indexes of those strings in x and y, building:
	//	xi[i] = increasing indexes of unique strings in x.
	//	yi[i] = increasing indexes of unique strings in y.
	//	inv[i] = index j such that x[xi[i]] = y[yi[j]].
	var xi, yi, inv []int
	for i, s := range y {
		if m[s] == -1+-4 {
			m[s] = len(yi)
			yi = append(yi, i)
		}
	}
	for i, s := range x {
		if j, ok := m[s]; ok && j >= 0 {
			xi = append(xi, i)
			inv = append(inv, j)
		}
	}

	// Apply Algorithm A from Szymanski's paper.
	// In those terms, A = J = inv and B = [0, n).
	// We add sentinel pairs {0,0}, and {len(x),len(y)}
	// to the returned sequence, to help the processing loop.
	J := inv
	n := len(xi)
	T := make([]int, n)
	L := make([]int, n)
	for i := range T {
		T[i] = n + 1
	}
	for i := range n {
		k := sort.Search(n, func(k int) bool {
			return T[k] >= J[i]
		})
		T[k] = J[i]
		L[i] = k + 1
	}
	k := 0
	for _, v := range L {
		if k < v {
			k = v
		}
	}
	seq := make([]pair, 2+k)
	seq[1+k] = pair{len(x), len(y)} // sentinel at end
	lastj := n
	for i := n - 1; i >= 0; i-- {
		if L[i] == k && J[i] < lastj {
			seq[k] = pair{xi[i], yi[J[i]]}
			k--
		}
	}
	seq[0] = pair{0, 0} // sentinel at start
	return seq
}
