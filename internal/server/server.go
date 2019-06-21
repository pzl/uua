package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/logger"
	"github.com/sirupsen/logrus"
)

type OptFunc func(*Cfg)

type server struct {
	router *chi.Mux
	srv    *http.Server
	cfg    *Cfg
	l      *logrus.Logger
}

type Cfg struct {
	Auths    []auth.Method
	Gen      uint64
	Addr     string
	TokenSig uua.Secrets
	SSLCert  string
	SSLKey   string
	JSONLog  bool
	Log      *logrus.Logger
}

func New(secrets uua.Secrets, auths []auth.Method, opts ...OptFunc) *server {
	cfg := Cfg{
		Addr:     ":6089",
		Gen:      1,
		Auths:    auths,
		TokenSig: secrets,
		SSLCert:  "",
		SSLKey:   "",
		JSONLog:  false,
	}

	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}

	if cfg.Log == nil {
		logger.New(cfg.JSONLog)
	}
	return &server{
		cfg: &cfg,
		l:   cfg.Log,
	}
}

func (s *server) Start(ctx context.Context) (err error) {
	s.router = chi.NewRouter()
	s.routes()

	s.l.WithFields(logrus.Fields{
		"Gen":  s.cfg.Gen,
		"Addr": s.cfg.Addr,
		"SSL":  s.cfg.SSLCert != "" && s.cfg.SSLKey != "",
	}).Debug("Starting UUA Server")

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
	}
	if s.cfg.SSLCert != "" && s.cfg.SSLKey != "" {
		s.srv.TLSConfig = sl
		s.srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
	} else {
		s.l.Warn("SSL disabled. Sending credentials over HTTP is not recommended")
	}

	ipv4, err := net.Listen("tcp4", s.cfg.Addr)
	if err != nil {
		return err
	}
	ipv6, err := net.Listen("tcp6", s.cfg.Addr)
	if err != nil {
		return err
	}

	errs := make(chan error)
	go s.listen(ipv4, s.cfg.SSLCert, s.cfg.SSLKey, errs)
	go s.listen(ipv6, s.cfg.SSLCert, s.cfg.SSLKey, errs)
	s.l.Infof("listening on %s", s.cfg.Addr)

	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	if err != nil && err != http.ErrServerClosed {
		s.l.WithError(err).Error("Http Server stopped unexpectedly")
		return err
	}
	s.l.Info("server stopped")
	return nil

}

func (s *server) listen(l net.Listener, cert, key string, errs chan<- error) {
	if cert != "" && key != "" {
		errs <- s.srv.ServeTLS(l, cert, key)
	} else {
		errs <- s.srv.Serve(l)
	}
}

func (s *server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
