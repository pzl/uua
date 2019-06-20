package main

import (
	"fmt"
	"os"

	"github.com/pzl/uua/internal/server"
)

func main() {
	secrets, auths, opts := parseCLI()

	s := server.New(secrets, auths, opts...)
	must(s.Start())
	// handle signals?
	defer must(s.Shutdown())
}

func must(e error) {
	if e != nil {
		exit(e.Error())
	}
}

func exit(s string) {
	fmt.Fprintln(os.Stderr, s)
	os.Exit(1)
}
