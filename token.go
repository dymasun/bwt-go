package jwt

import (
	"encoding/base64"
	"strings"
)

// Parse methods use this callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
type KeyBufFunc func([]string) (interface{}, error)

func SignedBuf(buf []byte, key interface{}, method SigningMethod) (string, error) {
	sstr := EncodeSegment([]byte(method.Alg())) + "." + EncodeSegment(buf)
	sig, err := method.Sign(sstr, key)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

func ParseToBytes(tokenString string, keyfunc KeyBufFunc) ([]byte, error) {
	return new(Parser).ParseToBytes(tokenString, keyfunc)
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
