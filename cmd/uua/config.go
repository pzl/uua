package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/logger"
	"github.com/pzl/uua/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

func parseCLI() (uua.Secrets, []auth.Method, []server.OptFunc) {
	pflag.StringP("addr", "a", ":6089", "Server listening Address")
	pflag.StringP("pass", "p", "", "symmetric encryption password")
	pflag.StringP("salt", "s", "", "symmetric encryption salt")
	pflag.StringP("sign-key", "k", "", "RSA private key file path, for signing")
	pflag.StringP("rsa", "r", "", "RSA private key string for signing. Recommended to use a file instead.")
	cfile := pflag.StringP("config", "c", "", "Config file to read values from")
	cdir := pflag.StringP("conf-dir", "d", "", "Search this directory for config files")
	pflag.Uint64P("gen", "g", 1, "current token generation. Set to 0 to disable")
	pflag.StringP("ssl-cert", "t", "", "path to SSL certificate file")
	pflag.StringP("ssl-key", "y", "", "path to SSL private key")
	pflag.BoolP("json", "j", false, "output logs in JSON formt")
	v := pflag.CountP("verbose", "v", "turn on verbose output. Can use multiple times")
	// @todo : -w bool flag for watching config for changes? need to propagate to handler

	pflag.Parse()

	log := logger.NewBuffered()
	switch *v {
	case 3:
		log.SetLevel(logrus.TraceLevel)
	case 2:
		log.SetLevel(logrus.DebugLevel)
	case 1:
		log.SetLevel(logrus.InfoLevel)
	default:
		log.SetLevel(logrus.WarnLevel)
	}

	k := koanf.New(".")
	searchDir(log, k, "/etc/uua/")
	searchDir(log, k, "/srv/apps/uua")
	// @todo XDG_CONFIG_HOME:-$HOME/.config/
	// XDG_CONFIG_DIRS:-/etc/xdg/
	searchDir(log, k, ".")
	if cdir := os.Getenv("CONFIG_DIR"); cdir != "" {
		searchDir(log, k, cdir) //search $CONFIG_DIR if passed in env
	}
	if cdir != nil && *cdir != "" {
		searchDir(log, k, *cdir) // load --conf-dir  if passed as a flag
	}
	if cfile != nil && *cfile != "" {
		// load explicit config file if passed as -c
		parser, err := determineParser(*cfile)
		must(err)
		must(k.Load(file.Provider(*cfile), parser))
	}

	// load environments next
	must(k.Load(env.Provider("", ".", func(key string) string {
		return strings.Replace(strings.ToLower(key), "_", "-", 0)
	}), nil))

	// load CLI flags last
	must(k.Load(posflag.Provider(pflag.CommandLine, "."), nil))

	// get configs
	var cfg struct {
		Pass        []byte
		Salt        []byte
		SignKey     string `koanf:"sign-key"`
		KeyMaterial string `koanf:"rsa"`
		Gen         uint64
		Addr        string
		SSLKey      string `koanf:"ssl-key"`
		SSLCert     string `koanf:"ssl-cert"`
		JSON        bool
		Auth        struct {
			Password map[string]string
		}
	}
	must(k.Unmarshal("", &cfg))
	logger.SetFormat(log, cfg.JSON)

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

	tokensWillPersist := true
	if cfg.Pass == nil || len(cfg.Pass) == 0 {
		tokensWillPersist = false
		log.Info("no token encryption password provided. Generating a random one")
		cfg.Pass = make([]byte, 32)
		_, err := rand.Read(cfg.Pass)
		must(err)
	}
	if cfg.Salt == nil || len(cfg.Salt) == 0 {
		tokensWillPersist = false
		log.Info("no encryption salt provided. Generating a random one")
		cfg.Salt = make([]byte, 32)
		_, err := rand.Read(cfg.Salt)
		must(err)
	}

	if key == nil {
		var err error
		tokensWillPersist = false
		log.Info("no RSA signing key provided. Generating one")
		key, err = rsa.GenerateKey(rand.Reader, 256)
		must(err)
	}

	if !tokensWillPersist {
		log.Warn("auto-generated credentials in use. Tokens will not be valid after shutdown")
	}

	if auths == nil || len(auths) == 0 {
		log.Warn("Warning: no authentication methods configured. Will not be able to login or generate new tokens")
	}

	opts := make([]server.OptFunc, 0, 4)
	opts = append(opts, func(sc *server.Cfg) { sc.Gen = cfg.Gen })
	opts = append(opts, func(sc *server.Cfg) { sc.Addr = cfg.Addr })
	opts = append(opts, func(sc *server.Cfg) { sc.JSONLog = cfg.JSON })
	opts = append(opts, func(sc *server.Cfg) { sc.Log = log })
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

func searchDir(log *logrus.Logger, k *koanf.Koanf, dir string) {
	exts := map[string]struct{}{
		".js":   struct{}{},
		".json": struct{}{},
		".toml": struct{}{},
		".tml":  struct{}{},
		".yaml": struct{}{},
		".yml":  struct{}{},
		".conf": struct{}{},
		".cnf":  struct{}{},
		".ini":  struct{}{},
	}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error { //nolint
		if err != nil {
			if !os.IsNotExist(err) {
				log.WithError(err).Error("unable to search config dir")
			}
			return err
		}

		l := log.WithFields(logrus.Fields{
			"path":  path,
			"name":  info.Name(),
			"isdir": info.IsDir(),
		})
		l.Trace("searching config dir..")

		if dir == info.Name() {
			l.Trace("skipping. Is top-level directory")
			return nil // top-level dir
		}

		if info.IsDir() {
			l.Trace("skipping, is directory")
			return filepath.SkipDir
		}
		filename := info.Name()
		li := strings.LastIndex(filename, ".")
		if li < 1 {
			l.Trace("skipping. Is hidden or no extension")
			return nil // starts with dot (hidden) or has no extension
		}
		name := filename[:li]
		if strings.ToLower(name) != "uua" {
			l.Trace("skipping, filename is not uua")
			return nil
		}
		ext := filename[li:]
		if _, ok := exts[ext]; ok {
			l.Trace("loading file!")
			parser, err := determineParser(filename)
			if err != nil {
				l.WithError(err).Error("unable to determine parser for file")
				return err
			}
			log.WithField("file", path).Debug("Loading config file")
			return k.Load(file.Provider(path), parser)
		}
		l.Trace("did not have the correct extension")
		return nil
	})
}

func determineParser(filename string) (koanf.Parser, error) {
	j := json.Parser()
	t := toml.Parser()
	y := yaml.Parser()

	exts := map[string]koanf.Parser{
		".js":   j,
		".json": j,
		".toml": t,
		".tml":  t,
		".yaml": y,
		".yml":  y,
		".conf": t, // process confs as inis... and inis as tomls
		".cnf":  t,
		".ini":  t,
	}

	ext := filepath.Ext(filename)
	if p, ok := exts[ext]; ok {
		return p, nil
	}

	// attempt to determine from file contents

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, 50)
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return nil, err
	}

	buf = bytes.TrimSpace(buf)
	// best guesses by syntax
	if buf[0] == '{' {
		return j, nil
	}
	if buf[0] == '[' {
		return t, nil
	}

	// looks like a yaml list somewhere in the file
	yamlList := regexp.MustCompile(`(?im)^\s*- \w+`)
	if yamlList.Match(buf) {
		return y, nil
	}

	// look at  key: value  vs key =
	eql := regexp.MustCompile(`(?im)^\w+\s*([=:])\s*`)
	if match := eql.FindSubmatch(buf); match != nil {
		switch match[1][0] {
		case ':':
			return y, nil
		case '=':
			return t, nil
		}
	}

	return nil, fmt.Errorf("no provider found for file %s", filename)
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
