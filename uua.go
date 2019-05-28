package uua

import "time"

type Token struct {
	Expiration time.Time
	Version    int
	User       string
}

func Decode(ts string) (bool, *Token) {
	// keys?!

	//validate signature
	// decrypt
	// check contents, expiration, version, revocation?

	return false, nil
}
