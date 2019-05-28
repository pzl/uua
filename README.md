Universal User Auth
=====================

`uua` is a Universal User Auth service.

You provide it with a token request: username, secret (password, key, something else). And it responds with an encrypted+signed token. 

The auth service can be provided with any token and responds with it's validity and claims.

This is basically JWE, in generic form.


*TODO*:

- revocation