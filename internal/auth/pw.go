package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/argon2"
)

var salted = []byte{0x30, 0x02, 0xde, 0x40}

type pw struct {
	valid map[string]string
}

func NewPassword(valid map[string]string) *pw {
	return &pw{
		valid: valid,
	}
}

func (p pw) Authenticate(r *http.Request, body io.Reader) (bool, *UInfo) {
	// read HTTP
	var req struct {
		User     string `json:"user"`
		Password string `json:"pass"`
		App      string `json:"app,omitempty"`
		Exp      int64  `json:"expires,omitempty"`
	}
	dec := json.NewDecoder(body)
	err := dec.Decode(&req)
	if err != nil {
		return false, nil
	}

	// look for stored hash for user
	hashed, found := p.valid[strings.ToLower(req.User)]
	if !found {
		return false, nil
	}

	// compare hashes
	h := argon2.IDKey([]byte(req.Password), salted, 1, 64*1024, 4, 32)
	if bytes.Equal([]byte(hashed), h) {
		return true, &UInfo{
			User: req.User,
			App:  req.App,
			Exp:  req.Exp,
		}
	}

	return false, nil
}
