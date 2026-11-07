package vectorgen

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hmacHKDF(ikm, salt []byte, info string, l int) []byte {
	if salt == nil {
		salt = make([]byte, 32)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < l; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write([]byte(info))
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:l]
}
