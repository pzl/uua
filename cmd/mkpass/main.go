package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/pzl/uua/internal/mkpass"
)

func main() {
	fmt.Fprint(os.Stderr, "Enter pass: ")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "")

	hash, salt, err := mkpass.Create(pass)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x.%x\n", hash, salt)
}
