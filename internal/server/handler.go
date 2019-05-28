package server

import (
	"net/http"

	"github.com/pzl/uua"
)

type Handler struct{}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	t := uua.Token{}
  _ = t
}

/*
	Verify accepts a token,

*/
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	ts := r.Context().Value("token").(string)

	valid, token := uua.Decode(ts)
	if !valid {
		//write the json
	}
	// return decoded token?!
  _ = token
}
