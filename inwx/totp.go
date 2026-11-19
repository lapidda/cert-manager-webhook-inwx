package inwx

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP as used by INWX ("GOOGLE-AUTH") is HMAC-SHA1.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP computes the 6-digit RFC 6238 code (HMAC-SHA1, 30 s step) for a
// base32 shared secret at time t. This is what authenticator apps compute
// from the secret INWX shows when 2FA is enabled.
//
// It is ~20 lines of standard library, so we do not pull in a dependency.
func TOTP(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.TrimSpace(secret)))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(key) == 0 {
		// Do not wrap err: base32 errors can quote parts of the input.
		return "", fmt.Errorf("inwx: TOTP shared secret is not valid base32")
	}

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30))

	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000), nil
}
