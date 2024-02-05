package github

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v54/github"
	giturl "github.com/kubescape/go-git-url"
)

// ParseGithubURL will parse a github URL and return the owner and repo name.
func ParseGithubURL(u string) (string, string, error) {
	gitURL, err := giturl.NewGitURL(u)
	if err != nil {
		return "", "", err
	}
	return gitURL.GetOwnerName(), gitURL.GetRepoName(), nil
}

func NewGithubRepoClient(client *github.Client, owner, repo string) *GithubRepoClient {
	return &GithubRepoClient{
		client: client,
		owner:  owner,
		repo:   repo,
	}
}

type GithubRepoClient struct {
	client *github.Client
	owner  string
	repo   string
}

func (grc *GithubRepoClient) Repo() string {
	return fmt.Sprintf("https://github.com/%s/%s", grc.owner, grc.repo)
}

// To show what all these different fields mean, we'll use the example of
// pycparser, which in pypi lists things as version 2.21, but the tag is
// listed as release_v2.21
type TagData struct {
	// Version of the tag. This is typically the same as the tag, but there are
	// differences. Sometimes the Version is 2.21 but tag is v2.21, or
	// release_v2.21, etc.
	// In our example, this would be 2.21
	Version string
	// Repo URL, for example https://github.com/eliben/pycparser
	Repo string
	// GitHub tag name. Full tag that GH knows, for example using above, this
	// would be the one that would be release_v2.21.
	Tag string
	// Commit SHA for this tag, for above: 3cf6bf5eb16f5eadd4a058e41596145c407a79ad
	SHA string
	// Some tags have a prefix. For our example, this would be release_v
	TagPrefix string
	// Is this the latest release from Github
	IsLatest bool
	// Is this the "newest" tag from GitHub. This is based on timestamp only
	// if there is not Latest release found.
	IsNewest bool
}

// GetTags will fetch the specified tags from the repo. Since API calls are
// rate limited, you should grab all the tags up front, and then pass them in
// here.
// Returns a map going from tag->TagData, where tag is typically the version,
// but again there are variances to this. Some versions for example are called
// v1.21, but the corresponding tag would be release_v1.21.
// You can explicitly pass a value for "highest" and it will then go through
// all the tags, and try to find the highest one based on the latest commit
// by timestamp. This is useful for example packages that don't have a
// releases, but just tags for example (github.com/eliben/pycparser)
func (grc *GithubRepoClient) GetTags(ctx context.Context, tags []string) (map[string]*TagData, error) {
	log := clog.FromContext(ctx)
	repo := grc.Repo()
	ret := map[string]*TagData{}
	// Populate the map with the tags we want to find, so they are easier
	// to look up in the for loop.
	lookForHighest := false
	for _, tag := range tags {
		ret[tag] = nil
		if tag == "highest" {
			lookForHighest = true
		}
	}
	found := 0
	// Assume nothing has been tagged before epoch...
	highest := time.Unix(0, 0)
	// Again, since we're limited by the API, we should grab as many tags per
	// call as we can.
	tagListOptions := &github.ListOptions{PerPage: 500}
	for {
		log.Infof("[%s] Getting tags page %d", repo, tagListOptions.Page)
		repoTags, res, err := grc.client.Repositories.ListTags(context.Background(), grc.owner, grc.repo, tagListOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to get tags for %s: %v", repo, err)
		}
		for _, tag := range repoTags {
			if _, ok := ret[*tag.Name]; ok {
				// We're looking for this, so fill in the SHA for it.
				log.Infof("[%s] found tag %s we're looking for with sha %s", repo, *tag.Name, *tag.Commit.SHA)
				ret[*tag.Name] = &TagData{
					Repo:    repo,
					Version: *tag.Name,
					Tag:     *tag.Name,
					SHA:     *tag.Commit.SHA,
				}
				found++
			} else {
				// This is super hackery, but for example, pycparser does not use
				// tags like 'v2.21', but instead uses 'release_v2.21', so we need
				// This can also happen if the version is v2.21 but the tag is 2.21
				for tagSuffix := range ret {
					if strings.HasSuffix(*tag.Name, tagSuffix) {
						log.Infof("[%s] found tag %s with suffix %s", repo, *tag.Name, tagSuffix)
						ret[tagSuffix] = &TagData{
							Repo:      repo,
							Version:   tagSuffix,
							Tag:       *tag.Name,
							SHA:       *tag.Commit.SHA,
							TagPrefix: strings.TrimSuffix(*tag.Name, tagSuffix)}
					}
				}
			}

			// If we're looking for the highest, we need to find the latest by
			// timestamp.
			if lookForHighest && tag.Commit.Committer.Date.After(highest) {
				ret[*tag.Name] = &TagData{
					Repo:     repo,
					Tag:      *tag.Name,
					SHA:      *tag.Commit.SHA,
					IsNewest: true,
				}
				highest = tag.Commit.Committer.Date.Time
			}
		}
		// If there's no more pages, or we found all the tags we're looking for,
		// we're done.
		// The only exception is if we are looking for the newest tag, which
		// we do if there are no releases.
		if res.NextPage == 0 || (found == len(tags) && !lookForHighest) {
			break
		}
		tagListOptions.Page = res.NextPage
	}
	// Remove nil entries from the map before returning so the caller doesn't
	// have to deal with it. There's probably better way...
	for k, v := range ret {
		if v == nil {
			delete(ret, k)
		}
	}
	return ret, nil
}

// GetVersions will try to find a version of the specified package. In addition
// to the specified version, it will try to find a latest version, and if it
// is different from the specified version, it will return it as well.
// There are quite a few different cases / heuristics here to cover. Some
// projects have a latest release, some don't. Some have releases, and some
// don't, and they just have tags, and so forth.
// I reckon there will be more heuristics coming as we learn.
func (grc *GithubRepoClient) GetVersions(ctx context.Context, version string) ([]TagData, error) {
	log := clog.FromContext(ctx)
	repo := grc.Repo()
	versions := []TagData{}
	// First, try to see if there's a latest release that is different
	// from the one that we're looking for.
	// Use case here is that many of the pypi packages lack behind, for example
	// conda, so grab the latest release if we can find it.
	// TODO(vaikas): We should capture the information on whether this repo
	// uses releases or not, and then use that to decide whether to set up the
	// Update.GithubMonitor.UseTags to true or false.
	latestRelease, _, err := grc.client.Repositories.GetLatestRelease(ctx, grc.owner, grc.repo)

	tagsToLook := []string{version}

	// Latest release is optional, so don't fail if we can't get it.
	latestReleaseVersion := ""
	switch {
	case err != nil:
		// This is not a fatal error, we don't give up that easy...
		log.Infof("[%s] failed to get latest release (this is fine there might be not be releases): %v", repo, err)
	case latestRelease != nil:
		// If latest is different from the version to look for, then add that in
		// here.
		latestReleaseVersion = *latestRelease.TagName
		if version != *latestRelease.Name {
			log.Infof("[%s] latest release is different from pypi, so fetching that too: %s", repo, *latestRelease.Name)
			tagsToLook = append(tagsToLook, *latestRelease.TagName)
		}
	default:
		// Lastly, if there is no latest release, look for the special "highest"
		// which is for cases like github.com/eliben/pycparser, where there are
		// no releases, but just tags.
		log.Infof("[%s] looks like there's no latest release so find the newest tag", repo)
		tagsToLook = append(tagsToLook, "highest")

	}
	tagData, err := grc.GetTags(ctx, tagsToLook)
	if err != nil {
		return nil, err
	}

	// Now that we have the tags, let's see what we got.
	for _, d := range tagData {
		log.Infof("[%s] got version %s with tag: %s commit %s and prefix %s", repo, d.Version, d.Tag, d.SHA, d.TagPrefix)
		if d.Version == latestReleaseVersion {
			d.IsLatest = true
		}
		versions = append(versions, *d)
	}
	return versions, nil
}
