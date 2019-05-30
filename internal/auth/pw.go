package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/pzl/uua/internal/mkpass"
)

type pw struct {
	valid map[string]Credential
}

type Credential struct {
	Hash []byte
	Salt []byte
}

func NewPassword(valid map[string]Credential) *pw {
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
	cred, found := p.valid[strings.ToLower(req.User)]
	if !found {
		return false, nil
	}

	// compare hashes
	if mkpass.Match([]byte(req.Password), cred.Salt, cred.Hash) {
		return true, &UInfo{
			User: req.User,
			App:  req.App,
			Exp:  req.Exp,
		}
	}
	return false, nil
}
