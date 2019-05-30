package main

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/pzl/uua/internal/mkpass"
)

func main() {
	fmt.Print("Enter pass: ")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Println("")

	hash, salt, err := mkpass.Create(pass)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x  %x\n", hash, salt)
}
