package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type computeClient struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

func newComputeClient(serverURL, token string, timeout time.Duration) (*computeClient, error) {
	parsed, err := url.ParseRequestURI(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("server_url must be absolute http(s) URL")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &computeClient{
		baseURL: parsed,
		token:   token,
		http:    &http.Client{Timeout: timeout},
	}, nil
}

func (c *computeClient) submitTask(ctx context.Context, task computeTask) (computeTask, error) {
	var out struct {
		Task computeTask `json:"task"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/tasks", task, http.StatusCreated, &out); err != nil {
		return computeTask{}, err
	}
	return out.Task, nil
}

func (c *computeClient) listTasks(ctx context.Context) ([]computeTask, error) {
	var out struct {
		Tasks  []computeTask `json:"tasks"`
		Stalls []any         `json:"stalls,omitempty"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/tasks", nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Tasks, nil
}

func (c *computeClient) doJSON(ctx context.Context, method, path string, body any, want int, out any) error {
	var requestBody *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}
	endpoint := c.baseURL.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: got status %d want %d", method, path, resp.StatusCode, want)
	}
	if out == nil {
		return nil
	}
	return decodeStrictJSON(resp.Body, out)
}
