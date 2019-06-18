package server

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/logger"
	"github.com/sirupsen/logrus"
)

func (s *server) Login(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLog(r)

	// make a copy of the body for each authenticator
	body, err := ioutil.ReadAll(r.Body)
	if err != nil && err != io.EOF {
		log.WithError(err).Error("error reading login body")
		errJS(w, "error reading body: "+err.Error())
		return
	}
	r.Body.Close()

	// verify credentials here...
	var u *auth.UInfo
	for _, a := range s.cfg.Auths {
		ok, uinfo := a.Authenticate(r, bytes.NewReader(body))
		if !ok {
			log.Info("authentication rejected")
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]string{
				"error": "invalid login",
			})
			return
		} else {
			log.WithField("user", uinfo.User).Info("authenticated successfully")
			u = uinfo
			break
		}
	}
	if u == nil {
		log.Error("no authentication available")
		errJS(w, "no authentication available")
		return
	}

	// All ok, create and respond with token
	log.WithFields(logrus.Fields{
		"user": u.User,
		"app":  u.App,
		"gen":  s.cfg.Gen,
		"exp":  u.Exp,
	}).Info("generating token")
	t := uua.New(u.User, u.App, s.cfg.Gen, time.Duration(u.Exp)*time.Second)
	tk, err := t.Encode(s.cfg.TokenSig)
	if err != nil {
		log.WithError(err).Error("error encoding or signing token")
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
func (s *server) Verify(w http.ResponseWriter, r *http.Request) {
	ts := r.Context().Value("token").(string)

	log := logger.GetLog(r)

	token, err := uua.Validate(ts, s.cfg.TokenSig, s.cfg.Gen)
	if err != nil {
		log.WithError(err).Info("token rejected")
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
