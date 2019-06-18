package main

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/server"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func main() {

	secrets, auths, opts := parseCLI()

	s := server.New(secrets, auths, opts...)
	must(s.Start())
	// handle signals?
	defer must(s.Shutdown())
}

func parseCLI() (uua.Secrets, []auth.Method, []server.OptFunc) {
	viper.SetConfigName("uua")
	viper.AddConfigPath("/srv/apps/uua")
	viper.AddConfigPath(".")

	setArgS("addr", "a", ":6089", "Server listening Address")
	setArgS("pass", "p", "", "symmetric encryption password")
	setArgS("salt", "s", "", "symmetric encryption salt")
	setArgS("sign-key", "k", "", "RSA private key file path, for signing", "SIGN_KEY")
	setArgS("rsa", "r", "", "RSA private key string for signing. Recommended to use a file instead.")
	setArgS("config", "c", "", "Config file to read values from", "CONFIG_FILE")
	setArgU("gen", "g", 1, "current token generation. Set to 0 to disable")
	setArgS("ssl-cert", "t", "", "path to SSL certificate file", "SSL_CERT")
	setArgS("ssl-key", "y", "", "path to SSL private key", "SSL_KEY")
	// @todo : -w bool flag for watching config for changes? need to propagate to handler

	pflag.Parse()
	must(viper.BindPFlags(pflag.CommandLine))

	// parse config file if found
	explicitConf := false
	if confFile := viper.GetString("config"); confFile != "" {
		explicitConf = true
		viper.SetConfigFile(confFile)
		/* Viper does not support overriding config file type https://github.com/spf13/viper/pull/535
		ext := filepath.Ext(confFile)
		switch ext {
		case "cfg", "config", "conf", "cnf", "":
			viper.SetConfigType("toml") // probably an INI, parse as toml, which will likely work
		default:
			viper.SetConfigType(ext)
		}
		*/
	}
	err := viper.ReadInConfig()
	if err != nil {
		_, nf := err.(viper.ConfigFileNotFoundError)
		if explicitConf {
			exit(err.Error())
		} else if !nf {
			exit(err.Error())
		}
	}

	// parse auth methods
	methods := viper.GetStringMap("auth")
	auths := make([]auth.Method, 0, len(methods))
	for method := range methods {
		switch method {
		case "password":
			users := viper.Sub("auth").GetStringMapString("password")
			creds := make(map[string]auth.Password)
			for uname, c := range users {
				hash, salt := parseHashString(c)
				creds[uname] = auth.Password{
					Hash: hash,
					Salt: salt,
				}
			}
			auths = append(auths, auth.NewPassword(creds))
		default:
			fmt.Printf("unrecognized authentication method: %s. Skipping\n", method)
			continue
		}
	}

	pass := viper.GetString("pass")
	salt := viper.GetString("salt")
	key := getKey(viper.GetString("sign-key"), viper.GetString("rsa"))
	gen := viper.GetUint64("gen")
	addr := viper.GetString("addr")
	sslKey := viper.GetString("ssl-key")
	sslCert := viper.GetString("ssl-cert")

	if pass == "" {
		exit("token encryption password is required")
	}
	if salt == "" {
		exit("token encryption salt is required")
	}
	if key == nil {
		exit("token RSA signing key is required")
	}

	if auths == nil || len(auths) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no authentication methods configured. Will not be able to login or generate new tokens")
	}

	opts := make([]server.OptFunc, 0, 4)
	opts = append(opts, func(cfg *server.Cfg) { cfg.Gen = gen })
	opts = append(opts, func(cfg *server.Cfg) { cfg.Addr = addr })
	if sslKey != "" {
		opts = append(opts, func(cfg *server.Cfg) { cfg.SSLKey = sslKey })
	}
	if sslCert != "" {
		opts = append(opts, func(cfg *server.Cfg) { cfg.SSLCert = sslCert })
	}
	return uua.Secrets{
		Pass: []byte(pass),
		Salt: []byte(salt),
		Key:  key,
	}, auths, opts
}

func setArgS(long string, short string, def string, help string, env ...string) {
	if def != "" {
		viper.SetDefault(long, def)
	}
	must(viper.BindEnv(append([]string{long}, env...)...))
	pflag.StringP(long, short, def, help)
}

func setArgU(long string, short string, def uint64, help string, env ...string) {
	viper.SetDefault(long, def)
	must(viper.BindEnv(append([]string{long}, env...)...))
	pflag.Uint64P(long, short, def, help)
}

func getKey(file string, content string) *rsa.PrivateKey {
	var err error
	var rsaBuf []byte

	if file == "" && content == "" {
		exit("error: no RSA file or text given")
	}

	if file != "" {
		rsaBuf, err = ioutil.ReadFile(file)
		if err != nil && err != io.EOF {
			exit(err.Error())
		}
	} else {
		rsaBuf = []byte(content)
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

func must(e error) {
	if e != nil {
		exit(e.Error())
	}
}

func exit(s string) {
	fmt.Fprintln(os.Stderr, s)
	os.Exit(1)
}
