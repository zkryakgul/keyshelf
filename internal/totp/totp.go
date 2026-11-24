// Package totp implements RFC 6238 time-based one-time passwords (HMAC-SHA1, 30 s, 6 digits), the
// variant every authenticator app supports. It is built on the standard library's crypto/hmac.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	Period = 30
	Digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("totp: random secret: %w", err)
	}
	return s, nil
}

// Code returns the code for time t.
func Code(secret []byte, t time.Time) string {
	return codeAt(secret, uint64(t.Unix()/Period), Digits)
}

func codeAt(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Verify checks code against the current step and one step either side. A step at or before lastStep
// is refused, so each code works once. It returns the step that matched.
func Verify(secret []byte, code string, t time.Time, lastStep int64) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	now := t.Unix() / Period
	for _, step := range []int64{now - 1, now, now + 1} {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(codeAt(secret, uint64(step), Digits)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// URI returns the otpauth:// link an authenticator app imports.
func URI(secret []byte, account string) string {
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {"keyshelf"}, "period": {"30"}, "digits": {"6"}}
	return "otpauth://totp/keyshelf:" + url.PathEscape(account) + "?" + q.Encode()
}
