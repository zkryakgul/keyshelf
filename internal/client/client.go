// Package client talks to a keyshelf server's /api/v1.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/zkryakgul/keyshelf/internal/store"
)

// Client is a keyshelf API client. Token may be empty for public calls.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Error is a non-2xx answer from the server.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status) }

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) do(method, path string, q url.Values, body io.Reader, ctype string) (*http.Response, error) {
	u := c.BaseURL + "/api/v1/" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach keyshelf at %s: %w", c.BaseURL, err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e struct{ Error string }
		json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return resp, nil
}

func (c *Client) json(method, path string, q url.Values, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ctype = bytes.NewReader(raw), "application/json"
	}
	resp, err := c.do(method, path, q, body, ctype)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type Status struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

func (c *Client) Status() (Status, error) {
	var s Status
	return s, c.json("GET", "status", nil, nil, &s)
}

func (c *Client) Unseal(passphrase string) error {
	return c.json("POST", "unseal", nil, map[string]string{"passphrase": passphrase}, nil)
}

func (c *Client) Recover(code, newPassphrase string) error {
	return c.json("POST", "recover", nil, map[string]string{"recovery_code": code, "new_passphrase": newPassphrase}, nil)
}

// Login returns an owner session token.
func (c *Client) Login(password, totpCode string) (string, time.Time, error) {
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := c.json("POST", "login", nil, map[string]string{"password": password, "totp": totpCode}, &out)
	return out.Token, out.ExpiresAt, err
}

func (c *Client) Logout() error { return c.json("POST", "logout", nil, nil, nil) }
func (c *Client) Seal() error   { return c.json("POST", "seal", nil, nil, nil) }

func (c *Client) Folders() ([]store.Folder, error) {
	var out []store.Folder
	return out, c.json("GET", "folders", nil, nil, &out)
}

func (c *Client) Entries(folder string, recursive bool, query string) ([]store.Entry, error) {
	q := url.Values{}
	if folder != "" {
		q.Set("folder", folder)
	}
	if recursive {
		q.Set("recursive", "1")
	}
	if query != "" {
		q.Set("q", query)
	}
	var out []store.Entry
	return out, c.json("GET", "entries", q, nil, &out)
}

func (c *Client) Entry(path string) (store.Entry, error) {
	var e store.Entry
	return e, c.json("GET", "entries/"+path, nil, nil, &e)
}

func (c *Client) PutEntry(path string, in store.EntryInput) (store.Entry, error) {
	var e store.Entry
	return e, c.json("PUT", "entries/"+path, nil, in, &e)
}

func (c *Client) DeleteEntry(path string) error {
	return c.json("DELETE", "entries/"+path, nil, nil, nil)
}

func fieldQuery(field string) url.Values { return url.Values{"field": {field}} }

// Value fetches a secret value. Callers must not print it unless asked to.
func (c *Client) Value(path, field string) ([]byte, error) {
	resp, err := c.do("GET", "values/"+path, fieldQuery(field), nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, store.MaxValueSize+1))
}

func (c *Client) PutValue(path, field string, value []byte) error {
	resp, err := c.do("PUT", "values/"+path, fieldQuery(field), bytes.NewReader(value), "application/octet-stream")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) DeleteValue(path, field string) error {
	return c.json("DELETE", "values/"+path, fieldQuery(field), nil, nil)
}

func (c *Client) Tokens() ([]store.Token, error) {
	var out []store.Token
	return out, c.json("GET", "tokens", nil, nil, &out)
}

func (c *Client) CreateToken(name string, scopes []store.Scope, ttl time.Duration) (string, store.Token, error) {
	var out struct {
		Token string      `json:"token"`
		Info  store.Token `json:"info"`
	}
	err := c.json("POST", "tokens", nil, map[string]any{"name": name, "scopes": scopes, "ttl_seconds": int64(ttl.Seconds())}, &out)
	return out.Token, out.Info, err
}

func (c *Client) RevokeToken(id int64) error {
	return c.json("DELETE", "tokens/"+strconv.FormatInt(id, 10), nil, nil, nil)
}

func (c *Client) Audit(target string, limit int) ([]store.Event, error) {
	q := url.Values{}
	if target != "" {
		q.Set("target", target)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out []store.Event
	return out, c.json("GET", "audit", q, nil, &out)
}

func (c *Client) TOTPSetup() (string, error) {
	var out struct {
		URI string `json:"otpauth_uri"`
	}
	return out.URI, c.json("POST", "totp/setup", nil, nil, &out)
}

func (c *Client) TOTPConfirm(code string) error {
	return c.json("POST", "totp/confirm", nil, map[string]string{"code": code}, nil)
}
