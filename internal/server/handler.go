package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
)

type Handler struct {
	cfg *Cfg
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// make a copy of the body for each authenticator
	body, err := ioutil.ReadAll(r.Body)
	if err != nil && err != io.EOF {
		errJS(w, "error reading body: "+err.Error())
		return
	}

	// verify credentials here...
	var u *auth.UInfo
	for _, a := range h.cfg.Auths {
		ok, uinfo := a.Authenticate(r, bytes.NewReader(body))
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]string{
				"error": "invalid login",
			})
			return
		} else {
			u = uinfo
			break
		}
	}
	if u == nil {
		errJS(w, "no authentication available")
		return
	}

	// All ok, create and respond with token
	t := uua.New(u.User, u.App, h.cfg.Gen, time.Duration(u.Exp)*time.Second)
	tk, err := t.Encode(h.cfg.TokenSig)
	if err != nil {
		errJS(w, err.Error())
		return
	}
	writeJSON(w, map[string]string{
		"token": tk,
	})
}

/*
	Verify accepts a token,
*/
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	ts := r.Context().Value("token").(string)

	token, err := uua.Validate(ts, h.cfg.TokenSig, h.cfg.Gen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token rejected: %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("{\"valid\":false}")) //nolint
		return
	}

	writeJSON(w, map[string]interface{}{
		"valid": true,
		"token": token,
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		errJS(w, "Could not encode JS: "+err.Error())
		return
	}
	w.Write(js)
}
