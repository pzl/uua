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

type Configurator struct {
	log *logrus.Logger
	k   *koanf.Koanf
}

func parseCLI() (uua.Secrets, []auth.Method, []server.OptFunc) {
	c := Configurator{
		log: logger.NewBuffered(),
		k:   koanf.New("."),
	}

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

	switch *v {
	case 3:
		c.log.SetLevel(logrus.TraceLevel)
	case 2:
		c.log.SetLevel(logrus.DebugLevel)
	case 1:
		c.log.SetLevel(logrus.InfoLevel)
	default:
		c.log.SetLevel(logrus.WarnLevel)
	}

	c.searchDir("/etc/uua/")
	c.searchDir(c.XDGConfigHome())
	c.searchDir(".")
	if cdir := os.Getenv("CONFIG_DIR"); cdir != "" {
		c.searchDir(cdir) //search $CONFIG_DIR if passed in env
	}
	if cdir != nil && *cdir != "" {
		c.searchDir(*cdir) // load --conf-dir  if passed as a flag
	}
	if cfile != nil && *cfile != "" {
		// load explicit config file if passed as -c
		parser, err := determineParser(*cfile)
		must(err)
		must(c.k.Load(file.Provider(*cfile), parser))
	}

	// load environments next
	must(c.k.Load(env.Provider("", ".", func(key string) string {
		return strings.Replace(strings.ToLower(key), "_", "-", 0)
	}), nil))

	// load CLI flags last
	must(c.k.Load(posflag.Provider(pflag.CommandLine, "."), nil))

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
	must(c.k.Unmarshal("", &cfg))
	logger.SetFormat(c.log, cfg.JSON)

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
	cfg.Pass, generated = c.genIfNotExists(cfg.Pass, "token encryption password")
	tokensWillPersist = tokensWillPersist && !generated
	cfg.Salt, generated = c.genIfNotExists(cfg.Salt, "encryption salt")
	tokensWillPersist = tokensWillPersist && !generated

	if key == nil {
		var err error
		tokensWillPersist = false
		c.log.Info("no RSA signing key provided. Generating one")
		key, err = rsa.GenerateKey(rand.Reader, 256)
		must(err)
	}

	if !tokensWillPersist {
		c.log.Warn("auto-generated credentials in use. Tokens will not be valid after shutdown")
	}
	if auths == nil || len(auths) == 0 {
		c.log.Warn("Warning: no authentication methods configured. Will not be able to login or generate new tokens")
	}

	opts := make([]server.OptFunc, 0, 4)
	opts = append(opts, func(sc *server.Cfg) { sc.Gen = cfg.Gen })
	opts = append(opts, func(sc *server.Cfg) { sc.Addr = cfg.Addr })
	opts = append(opts, func(sc *server.Cfg) { sc.JSONLog = cfg.JSON })
	opts = append(opts, func(sc *server.Cfg) { sc.Log = c.log })
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

func (c *Configurator) genIfNotExists(data []byte, name string) ([]byte, bool) {
	if data != nil && len(data) > 0 {
		return data, false
	}
	c.log.Infof("no %s provided. Generating a random one", name)
	data = make([]byte, 32)
	_, err := rand.Read(data)
	must(err)
	return data, true
}

func (c *Configurator) searchDir(dir string) {
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
				c.log.WithError(err).Error("unable to search config dir")
			}
			return err
		}

		l := c.log.WithFields(logrus.Fields{
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
			c.log.WithField("file", path).Debug("Loading config file")
			return c.k.Load(file.Provider(path), parser)
		}
		l.Trace("did not have the correct extension")
		return nil
	})
}

func determineParser(filename string) (koanf.Parser, error) {
	ext := filepath.Ext(filename)
	switch ext {
	case ".js", ".json":
		return json.Parser(), nil
	case ".toml", ".tml", ".conf", ".cnf", ".ini":
		return toml.Parser(), nil
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	}

	// attempt to determine from file contents
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, 50)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}

	buf = bytes.TrimSpace(buf)
	// best guesses by syntax
	switch buf[0] {
	case '{':
		return json.Parser(), nil
	case '[':
		return toml.Parser(), nil
	}

	// looks like a yaml list somewhere in the file
	if yamlList := regexp.MustCompile(`(?im)^\s*- \w+`); yamlList.Match(buf) {
		return yaml.Parser(), nil
	}

	// look at  key: value  vs key =
	eql := regexp.MustCompile(`(?im)^\w+\s*([=:])\s*`)
	if match := eql.FindSubmatch(buf); match != nil {
		switch match[1][0] {
		case ':':
			return yaml.Parser(), nil
		case '=':
			return toml.Parser(), nil
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

func (c *Configurator) XDGConfigHome() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "uua")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "uua")
	}
	return "/etc/xdg/uua"
}
