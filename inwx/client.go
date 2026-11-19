// Package inwx is a deliberately small client for the part of the INWX
// DomRobot JSON-RPC API that an ACME DNS-01 solver needs: log in, list the
// TXT records of a zone, create one, delete one, log out.
//
// API reference: https://www.inwx.de/en/help/apidoc
package inwx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	// LiveEndpoint is the production API.
	LiveEndpoint = "https://api.domrobot.com/jsonrpc/"
	// OTEEndpoint is the INWX test environment (separate accounts, no real DNS).
	OTEEndpoint = "https://api.ote.domrobot.com/jsonrpc/"

	codeObjectExists       = 2302
	codeObjectDoesNotExist = 2303

	maxResponseBytes = 4 << 20
)

// APIError is a non-success result code from INWX.
type APIError struct {
	Method string
	Code   int
	Msg    string
	Reason string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("inwx: %s failed with code %d: %s", e.Method, e.Code, e.Msg)
	if e.Reason != "" {
		s += " (" + e.Reason + ")"
	}
	return s
}

// IsNotFound reports whether err is INWX's "Object does not exist" (2303).
func IsNotFound(err error) bool { return hasCode(err, codeObjectDoesNotExist) }

// IsExists reports whether err is INWX's "Object exists" (2302).
func IsExists(err error) bool { return hasCode(err, codeObjectExists) }

func hasCode(err error, code int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// Record is one DNS record as returned by nameserver.info. Only the fields
// the solver needs are decoded; everything else (ttl, prio, ...) is ignored
// so that a type change there can never break us.
type Record struct {
	ID      ID     `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

// Client holds one INWX session. The session lives in a cookie, so a Client
// is meant to be created per operation: New, Login, work, Logout.
type Client struct {
	endpoint string
	http     *http.Client
}

// New returns a client for the given JSON-RPC endpoint.
func New(endpoint string) *Client {
	jar, _ := cookiejar.New(nil) // never returns an error with nil options
	return &Client{
		endpoint: endpoint,
		http:     &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}
}

type rpcRequest struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type rpcResponse struct {
	Code    int             `json:"code"`
	Msg     string          `json:"msg"`
	Reason  string          `json:"reason"`
	ResData json.RawMessage `json:"resData"`
}

// call performs one JSON-RPC call. Errors never contain the request
// parameters, because those carry the password and the TOTP code.
func (c *Client) call(ctx context.Context, method string, params, out any) error {
	if params == nil {
		params = struct{}{}
	}
	body, err := json.Marshal(rpcRequest{Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("inwx: %s: encode request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("inwx: %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cert-manager-webhook-inwx")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("inwx: %s: %w", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("inwx: %s: read response: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("inwx: %s: unexpected HTTP status %s", method, resp.Status)
	}
	var res rpcResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("inwx: %s: decode response: %w", method, err)
	}
	// EPP-style codes: 1xxx is success (1000 done, 1001 pending).
	if res.Code < 1000 || res.Code >= 2000 {
		return &APIError{Method: method, Code: res.Code, Msg: res.Msg, Reason: res.Reason}
	}
	if out != nil && len(res.ResData) > 0 {
		if err := json.Unmarshal(res.ResData, out); err != nil {
			return fmt.Errorf("inwx: %s: decode resData: %w", method, err)
		}
	}
	return nil
}

// Login opens a session. If the account has 2FA enabled, INWX answers the
// login with tfa="GOOGLE-AUTH" and the session stays locked until
// account.unlock is called with a current TOTP code; totp is asked for that
// code only then. Pass nil if no TOTP secret is configured.
func (c *Client) Login(ctx context.Context, user, pass string, totp func() (string, error)) error {
	var res struct {
		// "0" when 2FA is off. Decoded leniently in case it ever becomes a number.
		TFA json.RawMessage `json:"tfa"`
	}
	params := map[string]any{"user": user, "pass": pass, "lang": "en"}
	if err := c.call(ctx, "account.login", params, &res); err != nil {
		return err
	}
	tfa := strings.Trim(string(res.TFA), `" `)
	if tfa == "" || tfa == "0" || tfa == "null" {
		return nil
	}
	if totp == nil {
		return fmt.Errorf("inwx: account uses two-factor authentication (%s) but no TOTP secret is configured", tfa)
	}
	tan, err := totp()
	if err != nil {
		return err
	}
	return c.call(ctx, "account.unlock", map[string]any{"tan": tan}, nil)
}

// Logout ends the session.
func (c *Client) Logout(ctx context.Context) error {
	return c.call(ctx, "account.logout", nil, nil)
}

// TXTRecords lists all TXT records of a zone. It returns an error for which
// IsNotFound is true if the account has no zone with that name; the solver
// uses that to find the zone by walking up the name.
//
// We filter by type only and match names client-side: the API does not
// document whether record names are relative or fully qualified, so we do
// not depend on its name filter.
func (c *Client) TXTRecords(ctx context.Context, zone string) ([]Record, error) {
	var res struct {
		Record []Record `json:"record"`
	}
	params := map[string]any{"domain": zone, "type": "TXT"}
	if err := c.call(ctx, "nameserver.info", params, &res); err != nil {
		return nil, err
	}
	return res.Record, nil
}

// CreateTXT creates a TXT record. name is relative to the zone ("" for the apex).
func (c *Client) CreateTXT(ctx context.Context, zone, name, content string, ttl int) (ID, error) {
	var res struct {
		ID ID `json:"id"`
	}
	params := map[string]any{
		"domain":  zone,
		"type":    "TXT",
		"name":    name,
		"content": content,
		"ttl":     ttl,
	}
	if err := c.call(ctx, "nameserver.createRecord", params, &res); err != nil {
		return ID{}, err
	}
	return res.ID, nil
}

// DeleteRecord deletes a record by the id nameserver.info returned for it.
func (c *Client) DeleteRecord(ctx context.Context, id ID) error {
	return c.call(ctx, "nameserver.deleteRecord", map[string]any{"id": id}, nil)
}
