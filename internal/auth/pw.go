package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/pzl/mstk/logger"
	"github.com/pzl/uua/internal/mkpass"
)

type pw struct {
	valid map[string]Password
}

type Password struct {
	Hash []byte
	Salt []byte
}

func NewPassword(valid map[string]Password) *pw {
	return &pw{
		valid: valid,
	}
}

func (p pw) Authenticate(r *http.Request, body io.Reader) (bool, *UInfo) {
	log := logger.GetLog(r)

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
		log.WithError(err).Error("could not decode json body")
		return false, nil
	}

	// look for stored hash for user
	cred, found := p.valid[strings.ToLower(req.User)]
	if !found {
		log.WithField("user", req.User).Info("requested user is not a valid user")
		return false, nil
	}

	// compare hashes
	if mkpass.Match([]byte(req.Password), cred.Salt, cred.Hash) {
		log.Debug("password match")
		return true, &UInfo{
			User: req.User,
			App:  req.App,
			Exp:  req.Exp,
		}
	}
	log.Info("invalid password")
	return false, nil
}
