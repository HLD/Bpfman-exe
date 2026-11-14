package hunt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Client polls Edgewatch for follow-up tasks and posts each hunt's report back.
// It pulls, so warden never listens for commands. Edgewatch can only ask for the
// modes in Modes, each bounded in time.
type Client struct {
	Base  string // the webhook URL, e.g. http://127.0.0.1:8000/api/ingest/warden
	Token string
	HTTP  *http.Client
	Mgr   *Manager
}

func NewClient(webhook, token string) *Client {
	c := &Client{Base: strings.TrimRight(webhook, "/"), Token: token, HTTP: &http.Client{Timeout: 10 * time.Second}}
	c.Mgr = NewManager(func(r Report) { c.post(r) })
	return c
}

func (c *Client) do(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	return c.HTTP.Do(req)
}

// Poll fetches pending tasks and starts a hunt for each valid one.
func (c *Client) Poll(now time.Time) error {
	resp, err := c.do("GET", c.Base+"/tasks", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("tasks: %s", resp.Status)
	}
	var out struct {
		Tasks []Task `json:"tasks"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return err
	}
	for _, t := range out.Tasks {
		t, err := t.Clamp()
		if err != nil {
			slog.Warn("ignoring hunt task", "err", err)
			continue
		}
		if c.Mgr.Start(t, now) {
			slog.Info("hunt started", "id", t.ID, "mode", t.Mode, "seconds", t.Seconds)
		}
	}
	return nil
}

func (c *Client) post(r Report) {
	b, _ := json.Marshal(r)
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.do("POST", c.Base+"/tasks/"+r.TaskID+"/result", b)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				slog.Info("hunt reported", "id", r.TaskID, "mode", r.Mode, "events", r.Events, "notable", r.Notable)
				return
			}
			err = fmt.Errorf("status %s", resp.Status)
		}
		slog.Warn("hunt report failed", "id", r.TaskID, "err", err, "attempt", attempt+1)
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
}

// Run polls every interval and finishes due hunts every second, until ctx ends.
func (c *Client) Run(ctx context.Context, every time.Duration) {
	poll, tick := time.NewTicker(every), time.NewTicker(time.Second)
	defer poll.Stop()
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-poll.C:
			if err := c.Poll(now); err != nil {
				slog.Debug("task poll failed", "err", err)
			}
		case now := <-tick.C:
			c.Mgr.Finish(now)
		}
	}
}
