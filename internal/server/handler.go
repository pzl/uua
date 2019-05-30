package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
)

type Handler struct {
	s     uua.Secrets
	auths []auth.Method
	gen   uint64
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
	for _, a := range h.auths {
		ok, uinfo := a.Authenticate(r, bytes.NewReader(body))
		if !ok {
			fmt.Fprintf(w, "failed authentication strategy %v\n", a)
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
	t := uua.New(u.User, u.App, h.gen, time.Duration(u.Exp)*time.Second)
	tk, err := t.Encode(h.s)
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

	valid, token := uua.Validate(ts, h.s, h.gen)
	if !valid {
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
