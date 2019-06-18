package uua_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/pzl/uua"
)

func Example() bool {
	//  --- Creating a token ---

	// ideally, loaded from somewhere securely
	key, _ := rsa.GenerateKey(rand.Reader, 256)
	sec := uua.Secrets{
		Pass: []byte("encpass"),
		Salt: []byte("abc123"),
		Key:  key,
	}

	type Request struct {
		User     string
		Password string
		App      string
	}
	r := Request{} // receive login request however

	if r.User == "bob" && r.Password == "letmein" { // perform personal auth
		t := uua.New(r.User, r.App, 1, 30*time.Minute) // create a token
		ts, err := t.Encode(sec)                       // and serialize/encode it for sending
		if err != nil {
			panic(err)
		}
		fmt.Printf("response: %s\n", ts) // send token to user
	}

	// --- Validating a token ---

	ts := "64vlykYRouY5s..." // receive token from user request
	token, err := uua.Validate(ts, sec, 1)
	if err != nil {
		return false // invalid token (time expired, invalid signature, old generation)
	}

	// Valid token, authenticated user. Can check App or anything else.
	fmt.Printf("user: %s, App: %s\n", token.User, token.App)
	return true
}
