package relmon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	rlhttp "chainguard.dev/melange/internal/http"
	"golang.org/x/time/rate"
)

const searchFmt = "https://release-monitoring.org/api/v2/projects/?name=%s&ecosystem=pypi"

type Items struct {
	Items []Item `json:"items"`
}

type Item struct {
	Ecosystem string `json:"ecosystem"`
	Homepage  string `json:"homepage"`
	ID        int    `json:"id"`
}

func NewMonitorFinder() *MonitorFinder {
	return &MonitorFinder{
		Client: &rlhttp.RLHTTPClient{
			Client: http.DefaultClient,
			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
	}
}

type MonitorFinder struct {
	Client *rlhttp.RLHTTPClient
}

func (mf *MonitorFinder) FindMonitor(ctx context.Context, pkg string) (*Item, error) {
	var items *Items
	url := fmt.Sprintf(searchFmt, pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := mf.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cause := errors.New("http status return was not 200")
		err := fmt.Errorf("%d when getting %s: %w", resp.StatusCode, url, cause)
		return nil, err
	}

	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	if len(items.Items) == 0 {
		return nil, errors.New("no items found")
	}
	return &items.Items[0], nil
}
