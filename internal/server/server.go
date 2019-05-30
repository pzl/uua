package server

import (
	"fmt"
	"net/http"

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

	//ListenAndServe
	s.srv = &http.Server{
		Addr:    s.addr,
		Handler: s.router,
		//@todo: timeouts
	}
	err := s.srv.ListenAndServe() // blocks

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
