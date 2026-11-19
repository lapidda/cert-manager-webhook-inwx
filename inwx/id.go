package inwx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ID is an INWX record id.
//
// INWX documents record ids as "token255" (a string) today, but for years the
// API returned JSON numbers, and clients that hard-coded `int` broke when that
// changed. We do not care what the id *is*; we only need to hand it back to
// nameserver.deleteRecord. So ID keeps the exact JSON token it received and
// echoes it back unchanged, whichever form the API uses this year.
type ID struct {
	raw json.RawMessage
}

// UnmarshalJSON accepts a non-empty JSON string or a non-negative integer.
func (id *ID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0 || string(b) == "null":
		return errors.New("inwx: record id is missing")
	case b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("inwx: record id: %w", err)
		}
		if strings.TrimSpace(s) == "" {
			return errors.New("inwx: record id is an empty string")
		}
	default:
		for _, c := range b {
			if c < '0' || c > '9' {
				return fmt.Errorf("inwx: record id %q is neither a string nor an integer", b)
			}
		}
	}
	id.raw = append(json.RawMessage(nil), b...)
	return nil
}

// MarshalJSON returns the id in the same JSON form it was received in.
func (id ID) MarshalJSON() ([]byte, error) {
	if len(id.raw) == 0 {
		return nil, errors.New("inwx: cannot send an empty record id")
	}
	return id.raw, nil
}

// String returns the id without JSON quoting, for log messages.
func (id ID) String() string {
	return strings.Trim(string(id.raw), `"`)
}
