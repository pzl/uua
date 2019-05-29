package main

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	fmt.Print("Enter pass: ")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Print("\nEnter salt: ")
	salt, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	key := argon2.IDKey(pass, salt, 1, 64*1024, 4, 32)

	fmt.Printf("\n%x\n", key)
}
