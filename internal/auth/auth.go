package auth

import (
	"io"
	"net/http"
)

type UInfo struct {
	User string
	App  string
	Exp  int64
}

type AuthStrat interface {
	Authenticate(r *http.Request, body io.Reader) (bool, *UInfo)
}
