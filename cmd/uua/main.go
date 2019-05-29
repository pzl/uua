package main

import (
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	flags "github.com/jessevdk/go-flags"
	"github.com/pzl/uua"
	"github.com/pzl/uua/internal/server"
	"golang.org/x/crypto/ssh"
)

type Opts struct {
	RSAFile string `short:"f" long:"file" description:"RSA Key file to use for signing" value-name:"FILE" env:"RSAFILE"`
	RSA     string `short:"r" long:"rsa" description:"RSA private key text to use for signing. It is recommended to use file instead" env:"RSA"`
	Pass    string `short:"p" long:"pass" description:"Symmetric encryption pass" value-name:"PASS" env:"PASSWORD" required:"true"`
	Salt    string `short:"s" long:"salt" description:"Symmetric encryption salt" value-name:"SALT" env:"SALT" required:"true"`
	Gen     uint64 `short:"g" long:"generation" description:"current token generation. Set to 0 to disable" value-name:"GEN" env:"GENERATION" default:"1"`
	Addr    string `short:"a" long:"addr" description:"Server listening address" env:"ADDR" default:":1990" value-name:"ADDRESS"`
}

func main() {
	var opts Opts
	_, err := flags.Parse(&opts)
	if err != nil {
		exit("")
	}

	s := server.New(uua.Secrets{
		Pass: []byte(opts.Pass),
		Salt: []byte(opts.Salt),
		Key:  getKey(opts),
	}, opts.Gen, opts.Addr)
	err = s.Start()
	if err != nil {
		exit(err.Error())
	}
	// handle signals?
	defer s.Shutdown()
}

func getKey(o Opts) *rsa.PrivateKey {
	var err error
	var rsaBuf []byte

	if o.RSAFile == "" && o.RSA == "" {
		exit("error: no RSA file or text given")
	}

	if o.RSAFile != "" {
		rsaBuf, err = ioutil.ReadFile(o.RSAFile)
		if err != nil && err != io.EOF {
			exit(err.Error())
		}
	} else {
		rsaBuf = []byte(o.RSA)
	}

	k, err := ssh.ParseRawPrivateKey(rsaBuf)
	if err != nil {
		exit(err.Error())
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		exit("error: Not an RSA key")
	}
	return key
}

func exit(s string) {
	fmt.Fprintln(os.Stderr, s)
	os.Exit(1)
}
