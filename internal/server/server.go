package server

import (
	"net/http"

	"github.com/go-chi/chi"
)

type server struct {
	router *chi.Mux
	srv    *http.Server
	h      *Handler
	keys   struct{}
}

func New() *server {
	return &server{}
}

func (s *server) Start() error {
	// Read keys?

	s.router = chi.NewRouter()
	s.routes()

	return nil
}

func (s *server) Shutdown() error {
	return nil
}
