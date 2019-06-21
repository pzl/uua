package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pzl/uua/internal/server"
)

func main() {
	secrets, auths, opts := parseCLI()
	s := server.New(secrets, auths, opts...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, os.Kill, syscall.SIGQUIT)
		<-sigint
		cancel()
	}()
	must(s.Start(ctx))

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer must(s.Shutdown(ctx))
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
