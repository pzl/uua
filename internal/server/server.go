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

type OptFunc func(*Cfg)

type server struct {
	router *chi.Mux
	srv    *http.Server
	cfg    *Cfg
}

type Cfg struct {
	Auths    []auth.Method
	Gen      uint64
	Addr     string
	TokenSig uua.Secrets
	SSLCert  string
	SSLKey   string
}

func New(secrets uua.Secrets, auths []auth.Method, opts ...OptFunc) *server {
	cfg := Cfg{
		Addr:     ":6089",
		Gen:      1,
		Auths:    auths,
		TokenSig: secrets,
		SSLCert:  "server.crt",
		SSLKey:   "server.key",
	}

	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &server{
		cfg: &cfg,
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
		Addr:           s.cfg.Addr,
		Handler:        s.router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      sl,
		TLSNextProto:   make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	fmt.Printf("listening on %s\n", s.cfg.Addr)
	err := s.srv.ListenAndServeTLS(s.cfg.SSLCert, s.cfg.SSLKey) // blocks

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
