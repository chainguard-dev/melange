package relmon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	rlhttp "chainguard.dev/melange/pkg/http"
	"github.com/pkg/errors"
	"golang.org/x/time/rate"
)

const searchFmt = "https://release-monitoring.org/api/v2/projects/?name=%s&ecosystem=pypi"

type Items struct {
	Items []Item `json:"items"`
}

type Item struct {
	Ecosystem string `json:"ecosystem"`
	Homepage  string `json:"homepage"`
	Id        int    `json:"id"`
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
	var Items *Items
	url := fmt.Sprintf(searchFmt, pkg)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := mf.Client.Do(req)
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

	err = json.Unmarshal(data, &Items)
	if err != nil {
		return nil, err
	}
	if len(Items.Items) == 0 {
		return nil, errors.New("no items found")
	}
	return &Items.Items[0], nil
}
