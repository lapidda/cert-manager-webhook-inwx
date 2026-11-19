// Package inwxtest is an in-memory fake of the INWX JSON-RPC API for tests.
// It models exactly the behaviour the solver depends on, including the two
// things that vary in the real API: whether record ids are JSON numbers or
// strings, and whether record names are relative or fully qualified.
package inwxtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lapidda/cert-manager-webhook-inwx/inwx"
)

const cookieName = "domrobot"

// Record is a record held by the fake. Name is always the FQDN.
type Record struct {
	ID      int
	Zone    string
	Name    string
	Type    string
	Content string
	TTL     int
}

// Server is the fake. Set the option fields before the first request.
type Server struct {
	URL string

	User, Pass string
	// TOTPSecret, if set, makes the account 2FA-protected: login answers
	// tfa=GOOGLE-AUTH and the session is locked until account.unlock.
	TOTPSecret string
	Now        func() time.Time
	// StringIDs makes the API return record ids as JSON strings (as the real
	// API does today); otherwise as JSON numbers (as it used to).
	StringIDs bool
	// RelativeNames makes nameserver.info report names relative to the zone.
	RelativeNames bool

	mu       sync.Mutex
	zones    map[string]bool
	records  []Record
	nextID   int
	sessions map[string]*session
	calls    []string
}

type session struct{ locked bool }

// New starts a fake with the given zones and registers its shutdown.
func New(t *testing.T, zones ...string) *Server {
	t.Helper()
	s := &Server{
		User: "apiuser", Pass: "s3cret",
		Now:      time.Now,
		zones:    map[string]bool{},
		nextID:   1000,
		sessions: map[string]*session{},
	}
	for _, z := range zones {
		s.zones[z] = true
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(ts.Close)
	s.URL = ts.URL + "/jsonrpc/"
	return s
}

// Add puts a record into the fake directly and returns its id.
func (s *Server) Add(zone, fqdn, typ, content string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.add(zone, fqdn, typ, content, 300)
}

func (s *Server) add(zone, fqdn, typ, content string, ttl int) int {
	s.nextID++
	s.records = append(s.records, Record{ID: s.nextID, Zone: zone, Name: fqdn, Type: typ, Content: content, TTL: ttl})
	return s.nextID
}

// Remove deletes a record behind the solver's back.
func (s *Server) Remove(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remove(id)
}

func (s *Server) remove(id int) bool {
	for i, r := range s.records {
		if r.ID == id {
			s.records = append(s.records[:i], s.records[i+1:]...)
			return true
		}
	}
	return false
}

// Records returns a copy of all records.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.records...)
}

// TXT returns the TXT values at fqdn.
func (s *Server) TXT(fqdn string) []string {
	var out []string
	for _, r := range s.Records() {
		if r.Type == "TXT" && r.Name == fqdn {
			out = append(out, r.Content)
		}
	}
	return out
}

// Calls returns the methods called so far, in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// OpenSessions is the number of sessions that were not logged out.
func (s *Server) OpenSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string                     `json:"method"`
		Params map[string]json.RawMessage `json:"params"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, req.Method)

	str := func(k string) string {
		var v string
		_ = json.Unmarshal(req.Params[k], &v)
		return v
	}
	reply := func(code int, msg string, resData any) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"code": code, "msg": msg, "svTRID": "fake"}
		if resData != nil {
			out["resData"] = resData
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	ok := func(resData any) { reply(1000, "Command completed successfully", resData) }

	if req.Method == "account.login" {
		if str("user") != s.User || str("pass") != s.Pass {
			reply(2200, "Authentication error", nil)
			return
		}
		sid := fmt.Sprintf("sess-%d", len(s.calls))
		s.sessions[sid] = &session{locked: s.TOTPSecret != ""}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/"})
		tfa := "0"
		if s.TOTPSecret != "" {
			tfa = "GOOGLE-AUTH"
		}
		ok(map[string]any{"customerId": 1, "accountId": 1, "tfa": tfa})
		return
	}

	var sess *session
	var sid string
	if c, err := r.Cookie(cookieName); err == nil {
		sid, sess = c.Value, s.sessions[c.Value]
	}
	if sess == nil {
		reply(2200, "Authentication error", nil)
		return
	}

	switch req.Method {
	case "account.unlock":
		want, _ := inwx.TOTP(s.TOTPSecret, s.Now())
		if str("tan") != want {
			reply(2200, "Authentication error", nil)
			return
		}
		sess.locked = false
		ok(nil)
		return
	case "account.logout":
		delete(s.sessions, sid)
		reply(1500, "Command completed successfully; ending session", nil)
		return
	}

	if sess.locked {
		reply(2200, "Authentication error", nil)
		return
	}

	switch req.Method {
	case "nameserver.info":
		zone := str("domain")
		if !s.zones[zone] {
			reply(2303, "Object does not exist", nil)
			return
		}
		recs := []map[string]any{}
		for _, rec := range s.records {
			if rec.Zone != zone || (str("type") != "" && rec.Type != str("type")) {
				continue
			}
			name := rec.Name
			if s.RelativeNames {
				name = strings.TrimSuffix(strings.TrimSuffix(name, zone), ".")
			}
			recs = append(recs, map[string]any{
				"id": s.id(rec.ID), "name": name, "type": rec.Type,
				"content": rec.Content, "ttl": rec.TTL, "prio": 0,
			})
		}
		res := map[string]any{"roId": 1, "domain": zone, "type": "MASTER", "count": len(recs)}
		if len(recs) > 0 { // the real API omits "record" for an empty result
			res["record"] = recs
		}
		ok(res)

	case "nameserver.createRecord":
		zone := str("domain")
		if !s.zones[zone] {
			reply(2303, "Object does not exist", nil)
			return
		}
		name := str("name")
		fqdn := zone
		if name != "" && name != zone && !strings.HasSuffix(name, "."+zone) {
			fqdn = name + "." + zone
		} else if name != "" {
			fqdn = name
		}
		var ttl int
		_ = json.Unmarshal(req.Params["ttl"], &ttl)
		for _, rec := range s.records {
			if rec.Name == fqdn && rec.Type == str("type") && rec.Content == str("content") {
				reply(2302, "Object exists", nil)
				return
			}
		}
		ok(map[string]any{"id": s.id(s.add(zone, fqdn, str("type"), str("content"), ttl))})

	case "nameserver.deleteRecord":
		// Accept the id as number or string, like the real API.
		id, err := strconv.Atoi(strings.Trim(string(req.Params["id"]), `"`))
		if err != nil || !s.remove(id) {
			reply(2303, "Object does not exist", nil)
			return
		}
		ok(nil)

	default:
		reply(2000, "Unknown command", nil)
	}
}

func (s *Server) id(n int) any {
	if s.StringIDs {
		return strconv.Itoa(n)
	}
	return n
}
