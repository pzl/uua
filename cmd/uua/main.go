package main

import (
	"github.com/pzl/uua/internal/server"
)

func main() {
	s := server.New()
	err := s.Start()
	if err != nil {
		panic(err)
	}
	// handle signals?
	defer s.Shutdown()
}
