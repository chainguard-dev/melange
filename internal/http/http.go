package http

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"

	"github.com/chainguard-dev/clog"
	"golang.org/x/time/rate"
)

// RLHTTPClient Rate Limited HTTP Client
type RLHTTPClient struct {
	Client      *http.Client
	Ratelimiter *rate.Limiter
}

// Do dispatches the HTTP request to the network
func (c *RLHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.Ratelimiter != nil {
		// Comment out the below 5 lines to turn off ratelimiting
		err := c.Ratelimiter.Wait(req.Context()) // This is a blocking call. Honors the rate limit
		if err != nil {
			return nil, err
		}
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NewClient return rate_limited_http client with a ratelimiter
func NewClient(rl *rate.Limiter) *RLHTTPClient {
	c := &RLHTTPClient{
		Client:      http.DefaultClient,
		Ratelimiter: rl,
	}
	return c
}

// GetArtifactSHA256 attempts to pull the specified artifact and generate a
// sha256 hash of it.
//
// On success, it will return the sha256 hash as a string.
func (c *RLHTTPClient) GetArtifactSHA256(ctx context.Context, artifactURI string) (string, error) {
	clog.FromContext(ctx).Infof("Getting artifact %s", artifactURI)
	req, err := http.NewRequestWithContext(ctx, "GET", artifactURI, nil)
	if err != nil {
		return "", fmt.Errorf("creating request for %s: %w", artifactURI, err)
	}
	var client http.Client

	clog.FromContext(ctx).Infof("client.Do(%q)", artifactURI)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("getting %s: %w", artifactURI, err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%d when getting %s", resp.StatusCode, artifactURI)
	}
	h256 := sha256.New()
	if _, err := io.Copy(h256, resp.Body); err != nil {
		return "", fmt.Errorf("hashing %s: %w", artifactURI, err)
	}
	return fmt.Sprintf("%x", h256.Sum(nil)), nil
}
