package server

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func (s *server) routes() {

	//s.router.Use(middleware.RealIP) // X-Forwarded-For
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Heartbeat("/ping"))
	s.router.Use(middleware.Recoverer)
	s.router.Use(contentJSON)
	s.router.Use(HSTS)
	//https://github.com/go-chi/chi#auxiliary-middlewares--packages

	s.router.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(apiVer(1))
		v1.Post("/login", s.Login)
		v1.Post("/verify", getBodyToken(s.Verify))
	})

	s.router.NotFound(notFound())
}

type mware func(http.Handler) http.Handler

func apiVer(ver int) mware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), "api.version", ver))
			next.ServeHTTP(w, r)
		})
	}
}

func contentJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
// forces https
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func notFound() http.HandlerFunc {
	nf := []byte("{\"error\":\"not found\"}")

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write(nf) //nolint
	}
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
