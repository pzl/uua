package uua

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const CURRENT_VERSION = 1
const DEFAULT_EXP = 2 * time.Hour
const MAX_EXP = 24 * 365 * time.Hour

type Token struct {
	Expiration time.Time `json:"e"`
	Version    int       `json:"v"`
	User       string    `json:"u"`
	Generation uint64    `json:"g"`
	App        string    `json:"a"`
}

// used for serialization. Does not need to be called directly
func (t Token) MarshalJSON() ([]byte, error) {
	type Alias Token
	return json.Marshal(struct {
		Alias
		Expiration int64 `json:"e"`
	}{
		Alias:      Alias(t),
		Expiration: t.Expiration.Unix(),
	})
}

// used in deserialization. Does not need to be called directly
func (t *Token) UnmarshalJSON(data []byte) error {
	var Alias struct {
		Version    int    `json:"v"`
		User       string `json:"u"`
		App        string `json:"a"`
		Expiration int64  `json:"e"`
		Generation uint64 `json:"g"`
	}
	err := json.Unmarshal(data, &Alias)
	if err != nil {
		return err
	}
	t.Version = Alias.Version
	t.User = Alias.User
	t.App = Alias.App
	t.Expiration = time.Unix(Alias.Expiration, 0)
	t.Generation = Alias.Generation
	return nil
}

/*
Secrets represents the credentials required to encrypt and serialize a Token.

Tokens will be symmetrically encrypted with the given Pass and Salt, and then signed with the provided RSA Key.
*/
type Secrets struct {
	Pass []byte
	Salt []byte
	Key  *rsa.PrivateKey
}

/*
Creates a new Token object, unencrypted, unsigned. Once encoded with .Encode(secrets), it is a valid token string that can used to authenticate as a user.

It is up to you to validate credentials or access *before* granting a token.
*/
func New(user string, app string, gen uint64, exp time.Duration) Token {
	if exp == 0 || exp > MAX_EXP {
		exp = DEFAULT_EXP
	}
	return Token{
		Expiration: time.Now().Add(exp),
		Version:    CURRENT_VERSION,
		User:       user,
		App:        app,
		Generation: gen,
	}
}

/*
Validate token string `ts` given the secrets `s`. Optionally, use generation enforcement. Set gen=0 to disable.

Returns the token for a valid token string. Returns nil token and an error for an expired or otherwise invalid token.
*/
func Validate(ts string, s Secrets, gen uint64) (*Token, error) {
	spl := strings.Split(ts, ".")
	if len(spl) != 2 {
		return nil, fmt.Errorf("invalid token: not two halves split by '.'  length: %d", len(spl))
	}

	c64, s64 := []byte(spl[0]), []byte(spl[1])

	sig := make([]byte, base64.StdEncoding.DecodedLen(len(s64)))
	n, err := base64.StdEncoding.Decode(sig, s64)
	if err != nil {
		return nil, fmt.Errorf("invalid token: unable to b64 decode the signature: %v", err)
	}
	sig = sig[:n]

	//validate signature
	if !valid(c64, sig, &s.Key.PublicKey) {
		return nil, fmt.Errorf("invalid token: invalid signature")
	}

	t, err := Decode(spl[0], s)
	if err != nil {
		return nil, fmt.Errorf("unable to decode: %v", err)
	}

	// check contents, expiration, version, revocation?
	if time.Now().After(t.Expiration) {
		return nil, fmt.Errorf("invalid token: expired at %s. It is %s", t.Expiration, time.Now())
	}

	//
	if gen > 0 && t.Generation < gen {
		return nil, fmt.Errorf("invalid token: expired generation. Token gen: %d, current gen: %d", t.Generation, gen)
	}

	if t.Version != CURRENT_VERSION {
		return nil, fmt.Errorf("invalid token: not current version (got %d, want %d)", t.Version, CURRENT_VERSION)
	}
	return t, nil
}

/*
Decrypt a token string, without enforcing Generation, Expiration, or Signatures


This is not for use in authorizing users. But it may be used to check generation, expiration or contents.
*/
func Decode(ts string, s Secrets) (*Token, error) {
	spl := strings.Split(ts, ".")
	c64 := []byte(spl[0])

	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(c64)))
	n, err := base64.StdEncoding.Decode(ciphertext, c64)
	if err != nil {
		return nil, fmt.Errorf("invalid token: unable to b64 decode the token: %v", err)
	}
	ciphertext = ciphertext[:n]

	// decrypt
	plaintext, err := decrypt(s.Pass, s.Salt, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid token: could not decrypt: %v", err)
	}

	// deserialize
	t, err := deserialize(plaintext)
	if err != nil {
		return nil, fmt.Errorf("invalid token: could not deserialize: %v", err)
	}

	return t, nil
}

/*
Encrypts and signs the token as a usable Token string. This may be stored in cache files, cookies, etc.

Treat it as one would an API Key. It may have encrypted contents, but its the token itself that grants access.
*/
func (t Token) Encode(s Secrets) (string, error) {
	serialized, err := t.serialize()
	if err != nil {
		return "", err
	}

	enc, err := t.encrypt(s.Pass, s.Salt, serialized)
	if err != nil {
		return "", err
	}
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(enc)))
	base64.StdEncoding.Encode(b64, enc)

	sig, err := sign(b64, s.Key)
	if err != nil {
		return "", err
	}
	return string(b64) + "." + base64.StdEncoding.EncodeToString(sig), nil
}

func (t Token) serialize() ([]byte, error) { return json.Marshal(t) }

func deserialize(b []byte) (*Token, error) {
	var t Token
	err := json.Unmarshal(b, &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (t Token) encrypt(pass []byte, salt []byte, plaintext []byte) ([]byte, error) {
	gcm, err := setupCipher(pass, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(pass []byte, salt []byte, data []byte) ([]byte, error) {
	gcm, err := setupCipher(pass, salt)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func setupCipher(pass []byte, salt []byte) (cipher.AEAD, error) {
	// AES key is an argon2 hash of human password + salt
	key := argon2.IDKey(pass, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func sign(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(b)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil)
}

func valid(b []byte, sig []byte, key *rsa.PublicKey) bool {
	hash := sha256.Sum256(b)
	err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], sig, nil)
	return err == nil
}
