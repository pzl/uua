package main

import (
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/auth"
	"github.com/pzl/uua/internal/server"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func main() {

	secrets, auths, gen, addr := parseCLI()

	s := server.New(secrets, auths, gen, addr)
	err := s.Start()
	if err != nil {
		exit(err.Error())
	}
	// handle signals?
	defer s.Shutdown()
}

func parseCLI() (uua.Secrets, []auth.Method, uint64, string) {
	viper.SetConfigName("uua")
	viper.AddConfigPath("/srv/apps/uua")
	viper.AddConfigPath(".")

	setArgS("addr", "a", ":6089", "Server listening Address")
	setArgS("pass", "p", "", "symmetric encryption password")
	setArgS("salt", "s", "", "symmetric encryption salt")
	setArgS("file", "f", "", "RSA private key file path, for signing", "RSA_FILE")
	setArgS("rsa", "r", "", "RSA private key string for signing. Recommended to use a file instead.")
	setArgS("config", "c", "", "Config file to read values from", "CONFIG_FILE")
	setArgU("gen", "g", 1, "current token generation. Set to 0 to disable")

	pflag.Parse()
	must(viper.BindPFlags(pflag.CommandLine))

	if confFile := viper.GetString("conf"); confFile != "" {
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
	if _, nf := err.(viper.ConfigFileNotFoundError); err != nil && !nf {
		exit(err.Error())
	}

	pass := viper.GetString("pass")
	salt := viper.GetString("salt")
	key := getKey(viper.GetString("file"), viper.GetString("rsa"))
	gen := viper.GetUint64("gen")
	addr := viper.GetString("addr")
	auths := []auth.Method{}

	if pass == "" {
		exit("token encryption password is required")
	}
	if salt == "" {
		exit("token encryption salt is required")
	}
	if addr == "" {
		exit("server listening address is required")
	}
	if key == nil {
		exit("token RSA signing key is required")
	}
	if auths == nil || len(auths) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no authentication methods configured. Will not be able to login or generate new tokens")
	}

	return uua.Secrets{
		Pass: []byte(pass),
		Salt: []byte(salt),
		Key:  key,
	}, auths, gen, addr
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

func must(e error) {
	if e != nil {
		exit(e.Error())
	}
}

func exit(s string) {
	fmt.Fprintln(os.Stderr, s)
	os.Exit(1)
}
