package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
)

type server struct {
	router *chi.Mux
	srv    *http.Server
	h      *Handler
	addr   string
}

func New(secrets uua.Secrets, auths []auth.Method, gen uint64, addr string) *server {
	return &server{
		addr: addr,
		h: &Handler{
			s:     secrets,
			gen:   gen,
			auths: auths,
		},
	}
}

func (s *server) Start() error {
	s.router = chi.NewRouter()
	s.routes()

	// https://gist.github.com/denji/12b3a568f092ab951456#perfect-ssl-labs-score-with-go
	sl := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	//ListenAndServe
	s.srv = &http.Server{
		Addr:           s.addr,
		Handler:        s.router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      sl,
		TLSNextProto:   make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	fmt.Printf("listening on %s\n", s.addr)
	err := s.srv.ListenAndServeTLS("server.crt", "server.key") // blocks

	if err != http.ErrServerClosed {
		fmt.Printf("Http Server stopped unexpectedly: %v", err)
		s.Shutdown()
	} else {
		fmt.Printf("server stopped")
		return nil
	}
	return nil
}

func (s *server) Shutdown() error {
	return nil
}
