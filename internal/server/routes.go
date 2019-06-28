package server

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pzl/mstk"
)

func (s *server) routes() {
	s.router.Use(mstk.DefaultMiddleware(s.l)...)
	s.router.Use(HSTS)

	s.router.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(mstk.APIVer(1))
		v1.Post("/login", s.Login)
		v1.Post("/verify", getBodyToken(s.Verify))
	})

	s.router.NotFound(mstk.NotFound)
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
// forces https
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func errJS(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("{\"error\":\"" + msg + "\"}"))
	return
}

func getBodyToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errJS(w, "{\"error\":\"unable to read token\", \"detail\":\""+err.Error()+"\"}")
			return
		}

		token := bytes.TrimSpace(buf)
		if len(token) == 0 {
			errJS(w, "{\"error\", \"no token provided\"}")
			return
		}

		ctx := context.WithValue(r.Context(), "token", string(token))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
