package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/lapidda/cert-manager-webhook-inwx/internal/inwxtest"
)

const (
	testNS   = "cert-manager"
	testFQDN = "_acme-challenge.lab.example.com"
	baseCfg  = `{"usernameSecretRef":{"name":"inwx-credentials","key":"username"},
	             "passwordSecretRef":{"name":"inwx-credentials","key":"password"}}`
	totpCfg = `{"usernameSecretRef":{"name":"inwx-credentials","key":"username"},
	            "passwordSecretRef":{"name":"inwx-credentials","key":"password"},
	            "totpSecretRef":{"name":"inwx-credentials","key":"totp-secret"}}`
)

func newSolver(srv *inwxtest.Server, extra map[string]string) *solver {
	data := map[string][]byte{
		"username": []byte(srv.User),
		"password": []byte(srv.Pass + "\n"), // pasted secrets often end in a newline
	}
	for k, v := range extra {
		data[k] = []byte(v)
	}
	kube := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "inwx-credentials"},
		Data:       data,
	})
	return &solver{kube: kube, endpoint: srv.URL, now: srv.Now}
}

func challenge(key, cfg string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResourceNamespace: testNS,
		ResolvedFQDN:      testFQDN + ".",
		ResolvedZone:      "example.com.",
		Key:               key,
		Config:            &apiextensionsv1.JSON{Raw: []byte(cfg)},
	}
}

func assertTXT(t *testing.T, srv *inwxtest.Server, want ...string) {
	t.Helper()
	got := srv.TXT(testFQDN)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TXT at %s = %v, want %v", testFQDN, got, want)
	}
}

// The matrix covers what the real API has changed or leaves undocumented:
// ids as numbers vs strings (the bug that broke the old webhook), and record
// names relative vs fully qualified.
func TestPresentAndCleanUp(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		stringIDs, relativeNames bool
	}{
		{"numeric ids, fqdn names", false, false},
		{"string ids, fqdn names", true, false},
		{"string ids, relative names", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := inwxtest.New(t, "example.com")
			srv.StringIDs, srv.RelativeNames = tc.stringIDs, tc.relativeNames
			s := newSolver(srv, nil)

			if err := s.Present(challenge("key-1", baseCfg)); err != nil {
				t.Fatalf("Present: %v", err)
			}
			assertTXT(t, srv, "key-1")
			if r := srv.Records()[0]; r.TTL != defaultTTL || r.Zone != "example.com" {
				t.Errorf("record = %+v, want ttl %d in zone example.com", r, defaultTTL)
			}

			// Present is idempotent.
			if err := s.Present(challenge("key-1", baseCfg)); err != nil {
				t.Fatalf("second Present: %v", err)
			}
			assertTXT(t, srv, "key-1")

			if err := s.CleanUp(challenge("key-1", baseCfg)); err != nil {
				t.Fatalf("CleanUp: %v", err)
			}
			assertTXT(t, srv)

			if n := srv.OpenSessions(); n != 0 {
				t.Errorf("%d INWX sessions left open", n)
			}
		})
	}
}

// A wildcard and an apex certificate put two values at the same name.
// Each must be created and deleted on its own.
func TestMultipleTXTValues(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	srv.StringIDs = true
	s := newSolver(srv, nil)

	// Unrelated records must survive everything.
	srv.Add("example.com", "example.com", "TXT", "v=spf1 -all")
	srv.Add("example.com", "_acme-challenge.other.example.com", "TXT", "key-1")
	srv.Add("example.com", "lab.example.com", "A", "192.0.2.1")
	before := len(srv.Records())

	for _, k := range []string{"key-1", "key-2"} {
		if err := s.Present(challenge(k, baseCfg)); err != nil {
			t.Fatalf("Present %s: %v", k, err)
		}
	}
	assertTXT(t, srv, "key-1", "key-2")

	if err := s.CleanUp(challenge("key-1", baseCfg)); err != nil {
		t.Fatal(err)
	}
	assertTXT(t, srv, "key-2")

	if err := s.CleanUp(challenge("key-2", baseCfg)); err != nil {
		t.Fatal(err)
	}
	assertTXT(t, srv)
	if got := len(srv.Records()); got != before {
		t.Errorf("%d unrelated records left, want %d", got, before)
	}
}

func TestCleanUpMissingRecordIsNotAnError(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	srv.StringIDs = true
	s := newSolver(srv, nil)

	// Never presented.
	if err := s.CleanUp(challenge("key-1", baseCfg)); err != nil {
		t.Fatalf("CleanUp without record: %v", err)
	}
	// Presented, then cleaned up twice.
	if err := s.Present(challenge("key-1", baseCfg)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.CleanUp(challenge("key-1", baseCfg)); err != nil {
			t.Fatalf("CleanUp #%d: %v", i+1, err)
		}
	}
	for _, m := range srv.Calls() {
		if m == "nameserver.deleteRecord" {
			return
		}
	}
	t.Error("expected at least one deleteRecord call")
}

// cert-manager's ResolvedZone comes from public DNS and may not be the zone
// INWX holds; the solver then walks up from the FQDN.
func TestZoneIsFoundByWalkingUp(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	s := newSolver(srv, nil)

	ch := challenge("key-1", baseCfg)
	ch.ResolvedZone = "lab.example.com." // not a zone at INWX
	if err := s.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	assertTXT(t, srv, "key-1")
	if err := s.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
	assertTXT(t, srv)

	ch.ResolvedFQDN, ch.ResolvedZone = "_acme-challenge.unknown.org.", "unknown.org."
	if err := s.Present(ch); err == nil || !strings.Contains(err.Error(), "no INWX zone") {
		t.Fatalf("got %v, want a 'no INWX zone' error", err)
	}
	if n := srv.OpenSessions(); n != 0 {
		t.Errorf("%d INWX sessions left open after an error", n)
	}
}

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("p5y.de.", "_acme-challenge.lab.p5y.de.")
	want := []string{"p5y.de", "_acme-challenge.lab.p5y.de", "lab.p5y.de"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTwoFactor(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	srv.TOTPSecret = "JBSWY3DPEHPK3PXP"
	srv.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	// 2FA account but no totpSecretRef: clear error, nothing created.
	if err := newSolver(srv, nil).Present(challenge("key-1", baseCfg)); err == nil ||
		!strings.Contains(err.Error(), "two-factor") {
		t.Fatalf("got %v, want a two-factor error", err)
	}
	assertTXT(t, srv)

	s := newSolver(srv, map[string]string{"totp-secret": "jbsw y3dp ehpk 3pxp\n"})
	if err := s.Present(challenge("key-1", totpCfg)); err != nil {
		t.Fatalf("Present with TOTP: %v", err)
	}
	assertTXT(t, srv, "key-1")
	if err := s.CleanUp(challenge("key-1", totpCfg)); err != nil {
		t.Fatalf("CleanUp with TOTP: %v", err)
	}
	assertTXT(t, srv)

	unlocks := 0
	for _, m := range srv.Calls() {
		if m == "account.unlock" {
			unlocks++
		}
	}
	if unlocks != 2 {
		t.Errorf("account.unlock called %d times, want 2", unlocks)
	}
}

func TestConfigAndSecretErrors(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	s := newSolver(srv, nil)

	for name, cfg := range map[string]string{
		"missing refs":   `{}`,
		"ttl too low":    `{"ttl":60,"usernameSecretRef":{"name":"inwx-credentials","key":"username"},"passwordSecretRef":{"name":"inwx-credentials","key":"password"}}`,
		"missing key":    `{"usernameSecretRef":{"name":"inwx-credentials","key":"nope"},"passwordSecretRef":{"name":"inwx-credentials","key":"password"}}`,
		"missing secret": `{"usernameSecretRef":{"name":"other","key":"username"},"passwordSecretRef":{"name":"inwx-credentials","key":"password"}}`,
		"not json":       `nope`,
	} {
		if err := s.Present(challenge("key-1", cfg)); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.Contains(err.Error(), srv.Pass) {
			t.Errorf("%s: error leaks the password: %v", name, err)
		}
	}
	if calls := srv.Calls(); len(calls) != 0 {
		t.Errorf("INWX was called despite invalid config: %v", calls)
	}

	ch := challenge("key-1", baseCfg)
	ch.Config = nil
	if err := s.Present(ch); err == nil {
		t.Error("nil config: expected an error")
	}
}

func TestCustomTTL(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	s := newSolver(srv, nil)
	cfg := `{"ttl":600,"usernameSecretRef":{"name":"inwx-credentials","key":"username"},"passwordSecretRef":{"name":"inwx-credentials","key":"password"}}`
	if err := s.Present(challenge("key-1", cfg)); err != nil {
		t.Fatal(err)
	}
	if ttl := srv.Records()[0].TTL; ttl != 600 {
		t.Errorf("ttl = %d, want 600", ttl)
	}
}
