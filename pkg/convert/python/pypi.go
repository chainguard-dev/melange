package python

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	rlhttp "chainguard.dev/melange/pkg/http"
	"golang.org/x/time/rate"
)

type PackageIndex struct {
	url    string
	Client *rlhttp.RLHTTPClient
}

func NewPackageIndex(url string) *PackageIndex {
	p := &PackageIndex{
		url: url,
		Client: &rlhttp.RLHTTPClient{
			Client: http.DefaultClient,

			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
	}
	return p
}

// Package is the json response from  https://pypi.org/pypi/PACKAGE_NAME/json
// more details at https://warehouse.pypa.io/api-reference/json.html
type Package struct {
	Info         Info                 `json:"info"`
	LastSerial   int                  `json:"last_serial"`
	Releases     map[string][]Release `json:"releases"`
	URLs         []Release            `json:"urls"`
	Dependencies []string             `json:"dependencies"`
}

type Info struct {
	Author                 string            `json:"author"`
	AuthorEmail            string            `json:"author_email"`
	BugtrackURL            string            `json:"bugtrack_url"`
	Classifiers            []string          `json:"classifiers"`
	Description            string            `json:"description"`
	DescriptionContentType string            `json:"description_content_type"`
	DocsURL                string            `json:"docs_url"`
	DownloadURL            string            `json:"download_url"`
	Downloads              InfoDownloads     `json:"downloads"`
	HomePage               string            `json:"home_page"`
	Keywords               string            `json:"keywords"`
	License                string            `json:"license"`
	Maintainer             string            `json:"maintainer"`
	MaintainerEmail        string            `json:"maintainer_email"`
	Name                   string            `json:"name"`
	PackageURL             string            `json:"package_url"`
	Platform               string            `json:"platform"`
	ProjectURL             string            `json:"project_url"`
	ProjectURLs            map[string]string `json:"project_urls"`
	ReleaseURL             string            `json:"release_url"`
	RequiresDist           []string          `json:"requires_dist"`
	RequiresPython         string            `json:"requires_python"`
	Summary                string            `json:"summary"`
	Version                string            `json:"version"`
	Yanked                 bool              `json:"yanked"`
	YankedReason           string            `json:"yanked_reason"`
}

// GetSourceURL returns the source url for the package. This is sometimes
// Homepage, sometimes in the ProjectUrls as Homepage or Source.
func (i *Info) GetSourceURL() string {
	if strings.Contains(i.HomePage, "github.com") {
		return i.HomePage
	}
	if strings.Contains(i.ProjectURLs["Homepage"], "github.com") {
		return i.ProjectURLs["Homepage"]
	}
	if strings.Contains(i.ProjectURLs["Source"], "github.com") {
		return i.ProjectURLs["Source"]
	}
	return ""
}

type InfoDownloads struct {
	LastDay   int `json:"last_day"`
	LastMonth int `json:"last_month"`
	LastWeek  int `json:"last_week"`
}

type Release struct {
	CommentText       string         `json:"comment_text"`
	Digest            ReleaseDigests `json:"digests"`
	Downloads         int            `json:"downloads"`
	Filename          string         `json:"filename"`
	HasSig            bool           `json:"has_sig"`
	Md5Digest         string         `json:"md5_digest"`
	PackageType       string         `json:"packagetype"`
	PythonVersion     string         `json:"python_version"`
	Size              int            `json:"size"`
	UploadTimeIso8601 string         `json:"upload_time_iso_8601"`
	URL               string         `json:"url"`
	Yanked            bool           `json:"yanked"`
	YankedReason      string         `json:"yanked_reason"`
}

type ReleaseDigests struct {
	Md5    string `json:"md5"`
	Sha256 string `json:"sha256"`
}

// CheckSourceDeps not all packages list requirements, so we may need to dive into the source code to find deps
func (p *PackageIndex) CheckSourceDeps(projectName string) error {
	return nil
}

func (p *PackageIndex) Get(ctx context.Context, projectName, version string) (*Package, error) {
	if version == "" {
		return p.GetLatest(ctx, projectName)
	}
	return p.GetVersion(ctx, projectName, version)
}

func (p *PackageIndex) GetLatest(ctx context.Context, projectName string) (*Package, error) {
	endpoint := fmt.Sprintf("pypi/%s/json", projectName)
	return p.packageReq(ctx, endpoint)
}

func (p *PackageIndex) GetVersion(ctx context.Context, projectName, version string) (*Package, error) {
	endpoint := fmt.Sprintf("pypi/%s/%s/json", projectName, version)
	return p.packageReq(ctx, endpoint)
}

func (p *PackageIndex) packageReq(ctx context.Context, endpoint string) (*Package, error) {
	var pkg *Package

	url := fmt.Sprintf("%s/%s", p.url, endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		cause := errors.New("http status return was not 200")
		err := errors.Wrapf(cause, "%d when getting %s", resp.StatusCode, url)
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &pkg)
	if err != nil {
		return nil, err
	}
	return pkg, err
}
