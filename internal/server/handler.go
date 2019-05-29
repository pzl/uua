package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/pzl/uua"
)

type Handler struct {
	s   uua.Secrets
	gen uint64
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		App  string `json:"app,omitempty"`
		Exp  int64  `json:"exp,omitempty"`
	}

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil && err != io.EOF {
		errJS(w, err.Error())
		return
	}

	// verify credentials here...

	// All ok, create and respond with token
	t := uua.New(req.User, req.App, h.gen, time.Duration(req.Exp)*time.Second)
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

	valid, token := uua.Decode(ts, h.s, h.gen)
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
