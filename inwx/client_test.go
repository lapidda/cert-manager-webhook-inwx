package inwx_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lapidda/cert-manager-webhook-inwx/internal/inwxtest"
	"github.com/lapidda/cert-manager-webhook-inwx/inwx"
)

func TestIDRoundTrip(t *testing.T) {
	for _, in := range []string{`12345`, `"12345"`, `"abc-1"`} {
		var id inwx.ID
		if err := json.Unmarshal([]byte(in), &id); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		out, err := json.Marshal(map[string]any{"id": id})
		if err != nil {
			t.Fatalf("marshal %s: %v", in, err)
		}
		if want := `{"id":` + in + `}`; string(out) != want {
			t.Errorf("round trip: got %s, want %s", out, want)
		}
		if got := id.String(); strings.Contains(got, `"`) {
			t.Errorf("String() = %s, want it unquoted", got)
		}
	}
	for _, bad := range []string{`null`, `""`, `1.5`, `-1`, `true`, `{}`} {
		var id inwx.ID
		if err := json.Unmarshal([]byte(bad), &id); err == nil {
			t.Errorf("unmarshal %s: expected an error", bad)
		}
	}
	if _, err := json.Marshal(inwx.ID{}); err == nil {
		t.Error("marshalling the zero ID must fail rather than send null")
	}
}

// RFC 6238 appendix B test vectors (SHA-1), truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1234567890:  "005924",
		20000000000: "353130",
	} {
		got, err := inwx.TOTP(secret, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
	// Authenticator-style formatting: lower case, spaces, padding.
	spaced := strings.ToLower(secret[:4] + " " + secret[4:])
	if got, err := inwx.TOTP(spaced, time.Unix(59, 0)); err != nil || got != "287082" {
		t.Errorf("formatted secret: got %q, %v", got, err)
	}
}

func TestTOTPInvalidSecretDoesNotLeak(t *testing.T) {
	_, err := inwx.TOTP("not!base32!SECRETVALUE", time.Now())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Errorf("error leaks the secret: %v", err)
	}
}

func TestLoginFailureDoesNotLeakPassword(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	err := inwx.New(srv.URL).Login(context.Background(), srv.User, "wrong-PASSWORD-123", nil)
	if err == nil {
		t.Fatal("expected a login error")
	}
	if strings.Contains(err.Error(), "wrong-PASSWORD-123") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestRecordLifecycle(t *testing.T) {
	for _, stringIDs := range []bool{false, true} {
		srv := inwxtest.New(t, "example.com")
		srv.StringIDs = stringIDs
		ctx := context.Background()
		c := inwx.New(srv.URL)

		if err := c.Login(ctx, srv.User, srv.Pass, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := c.TXTRecords(ctx, "nope.example.com"); !inwx.IsNotFound(err) {
			t.Fatalf("unknown zone: got %v, want not found", err)
		}
		if _, err := c.CreateTXT(ctx, "example.com", "_acme-challenge", "v1", 300); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CreateTXT(ctx, "example.com", "_acme-challenge", "v1", 300); !inwx.IsExists(err) {
			t.Fatalf("duplicate create: got %v, want exists", err)
		}
		recs, err := c.TXTRecords(ctx, "example.com")
		if err != nil || len(recs) != 1 {
			t.Fatalf("TXTRecords = %v, %v", recs, err)
		}
		if err := c.DeleteRecord(ctx, recs[0].ID); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteRecord(ctx, recs[0].ID); !inwx.IsNotFound(err) {
			t.Fatalf("second delete: got %v, want not found", err)
		}
		if err := c.Logout(ctx); err != nil {
			t.Fatal(err)
		}
		if n := srv.OpenSessions(); n != 0 {
			t.Errorf("stringIDs=%v: %d sessions left open", stringIDs, n)
		}
	}
}

func TestLoginWith2FA(t *testing.T) {
	srv := inwxtest.New(t, "example.com")
	srv.TOTPSecret = "JBSWY3DPEHPK3PXP"
	ctx := context.Background()

	// Without a TOTP source the login must fail with a clear message.
	if err := inwx.New(srv.URL).Login(ctx, srv.User, srv.Pass, nil); err == nil ||
		!strings.Contains(err.Error(), "two-factor") {
		t.Fatalf("got %v, want a two-factor error", err)
	}

	c := inwx.New(srv.URL)
	totp := func() (string, error) { return inwx.TOTP(srv.TOTPSecret, srv.Now()) }
	if err := c.Login(ctx, srv.User, srv.Pass, totp); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TXTRecords(ctx, "example.com"); err != nil {
		t.Fatalf("session should be unlocked: %v", err)
	}

	// A wrong code leaves the session locked.
	bad := inwx.New(srv.URL)
	if err := bad.Login(ctx, srv.User, srv.Pass, func() (string, error) { return "000000", nil }); err == nil {
		t.Fatal("expected unlock to fail with a wrong code")
	}
	if _, err := bad.TXTRecords(ctx, "example.com"); err == nil {
		t.Fatal("locked session must not be usable")
	}
}
