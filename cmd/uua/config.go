package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/pzl/mstk"
	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

type Cfg struct {
	Pass        []byte
	Salt        []byte
	SignKey     string `koanf:"sign-key"`
	KeyMaterial string `koanf:"rsa"`
	Gen         uint64
	Addr        string
	SSLKey      string `koanf:"ssl-key"`
	SSLCert     string `koanf:"ssl-cert"`
	Auth        struct {
		Password map[string]string
	}
}

func parseCLI() (uua.Secrets, []auth.Method, []server.OptFunc) {
	c := mstk.NewConfig("uua")
	c.SetFlags(func(f *pflag.FlagSet) {
		f.StringP("addr", "a", ":6089", "Server listening Address")
		f.StringP("pass", "p", "", "symmetric encryption password")
		f.StringP("salt", "s", "", "symmetric encryption salt")
		f.StringP("sign-key", "k", "", "RSA private key file path, for signing")
		f.StringP("rsa", "r", "", "RSA private key string for signing. Recommended to use a file instead.")
		f.Uint64P("gen", "g", 1, "current token generation. Set to 0 to disable")
		f.StringP("ssl-cert", "t", "", "path to SSL certificate file")
		f.StringP("ssl-key", "y", "", "path to SSL private key")
		f.AddFlagSet(mstk.CommonFlags())
		// @todo : -w bool flag for watching config for changes? need to propagate to handler
	})
	c.Parse()

	var cfg Cfg
	must(c.K.Unmarshal("", &cfg))

	// parse auth methods
	passwds := make(map[string]auth.Password, len(cfg.Auth.Password))
	for user, pass := range cfg.Auth.Password {
		hash, salt := parseHashString(pass)
		passwds[user] = auth.Password{
			Hash: hash,
			Salt: salt,
		}
	}
	var auths []auth.Method
	if len(passwds) > 0 {
		auths = []auth.Method{auth.NewPassword(passwds)}
	}

	key := getKey(cfg.SignKey, cfg.KeyMaterial)

	var generated bool
	tokensWillPersist := true
	cfg.Pass, generated = genIfNotExists(cfg.Pass, "token encryption password", c.Log)
	tokensWillPersist = tokensWillPersist && !generated
	cfg.Salt, generated = genIfNotExists(cfg.Salt, "encryption salt", c.Log)
	tokensWillPersist = tokensWillPersist && !generated

	if key == nil {
		var err error
		tokensWillPersist = false
		c.Log.Info("no RSA signing key provided. Generating one")
		key, err = rsa.GenerateKey(rand.Reader, 256)
		must(err)
	}

	if !tokensWillPersist {
		c.Log.Warn("auto-generated credentials in use. Tokens will not be valid after shutdown")
	}
	if auths == nil || len(auths) == 0 {
		c.Log.Warn("Warning: no authentication methods configured. Will not be able to login or generate new tokens")
	}

	opts := make([]server.OptFunc, 0, 4)
	opts = append(opts, func(sc *server.Cfg) { sc.Gen = cfg.Gen })
	opts = append(opts, func(sc *server.Cfg) { sc.Addr = cfg.Addr })
	opts = append(opts, func(sc *server.Cfg) { sc.Log = c.Log })
	if cfg.SSLKey != "" {
		opts = append(opts, func(sc *server.Cfg) { sc.SSLKey = cfg.SSLKey })
	}
	if cfg.SSLCert != "" {
		opts = append(opts, func(sc *server.Cfg) { sc.SSLCert = cfg.SSLCert })
	}

	return uua.Secrets{
		Pass: cfg.Pass,
		Salt: cfg.Salt,
		Key:  key,
	}, auths, opts
}

func genIfNotExists(data []byte, name string, log *logrus.Logger) ([]byte, bool) {
	if data != nil && len(data) > 0 {
		return data, false
	}
	log.Infof("no %s provided. Generating a random one", name)
	data = make([]byte, 32)
	_, err := rand.Read(data)
	must(err)
	return data, true
}

func getKey(file string, content string) *rsa.PrivateKey {
	var err error
	var rsaBuf []byte

	if file != "" {
		rsaBuf, err = ioutil.ReadFile(file)
		if err != nil && err != io.EOF {
			exit(err.Error())
		}
	} else if content != "" {
		rsaBuf = []byte(content)
	}

	if rsaBuf == nil {
		return nil
	}
	k, err := ssh.ParseRawPrivateKey(rsaBuf)
	must(err)
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		exit("error: Not an RSA key")
	}
	return key
}

func parseHashString(s string) (hash []byte, salt []byte) {
	var err error
	spl := strings.Split(s, ".")
	if len(spl) != 2 {
		exit(fmt.Sprintf("invalid password format: %s\nexpecting format HASH.SALT\n", s))
	}
	hash, err = hex.DecodeString(spl[0])
	must(err)
	salt, err = hex.DecodeString(spl[1])
	must(err)
	return hash, salt
}
