Universal User Auth
=====================

`uua` is a Universal User Auth microservice. 

You provide it with a token request (login): username, secret (password, key, something else). And it responds with an encrypted+signed token. When the service is provided with a token, it validates the token and returns it's content (user, app, etc).

This is basically a [JWT](https://jwt.io/), or JWE flavor since it's encrypted, without the header. 


Usage
------

```sh
ssh-keygen -t rsa -f private_rsa # create a signing RSA key
uua -p somepass -s mysalt -f private_rsa
```

to avoid specifying credentials on the command line, you can use ENV vars, or a config file:

```sh
ssh-keygen -t rsa -f private_rsa # create a signing RSA key
echo "
file: private_rsa
pass: encpass
salt: x3*h9dw0e
" > config.yml # create a config file
CONFIG_FILE=config.yml
uua  # or -c config.yml
```

The parameters are processed in the following precedence, highest first:

1) Command line arg (e.g. `-s mysalt56`)
1) Env var (e.g. `SALT=somesalt`)
1) Config file (via `-c FILEPATH`)  (supported extensions: `json, toml, yaml, yml` for all config files)
1) Config file (via `$CONFIG_FILE` env)
1) Config file (via default search paths)
1) Default values (generation and listen address have defaults)

The arguments are:

```
  -p, --pass string   symmetric encryption password               ENV: PASS
  -s, --salt string   symmetric encryption salt                   ENV: SALT
  -r, --rsa string    RSA private key string for signing. Recommended to use a file instead.  ENV: RSA
  -f, --file string   RSA private key file path, for signing      ENV: RSA_FILE
  -a, --addr string   Server listening Address (default ":6089")  ENV: ADDR
  -g, --gen uint      current token generation. Set to 0 to disable (default 1) ENV: GEN
  -c, --conf string   Config file to read values from             ENV: CONFIG_FILE
```


The required parameters (via any method above) are: **pass**, **salt**, and an RSA key, _either_ through **rsa** or **file**. 

The key names for these properties match their `--long` flag names. I.e. `--pass` will be `pass: x`


The Token
----------

A token looks like this:

```
nNSmKIDSZl6tguSjz0buFpC/gowjIN1A6dPwkYoAVoekBVbvxUsGcR818nWDGeYUVaykA3Sr8fM+Pwa
L/y4m8OrOO/DpQNY+.JmezsGZb/zardmNWMub2tPU/ln2xtjYbhpEWcbzTQZ8EoxLWpcJ0IQGO5hEB1
FEBz8k4ghKnsETZ0ozfFNoSOQv/yMGCUwtFpdK7KjYpWqxEgi/Kkt198uoXmJNQcm8y5eBkI4/FbbTB
am0cbYQaSIGI6bjiFZ8Xhem5HzS/oTFWZT/uXzSGe4JGcO8BgoWRIEoXQY4Mcpzcl43Zgt3o+KH/U/Q
arIqNkFgIo2SpQR5qFIxovXkma05I/fOZ6YaxduXvAFQNjrSIImfNguGOb6aTqEr5un1YxMSSc9ojK/
+vK+UolZSWO6H5QJ42+3fKuwsxkjit7BQ4yq5sGry7Rw==
```

It is dot (`.`) separated, like a JWT. The first section is `Base64(AES-256-GCM(JSON(content)))`. Where `content` is currently made up of the fields: 

- **Expiration**, time
- **User**
- **App**, which application requested the token
- **Version**, the UUA lib version
- **Generation**, your app version

The `User` field may be used to identify your own user in whatever way you see fit. Any string that uniquely identifies a user (email address, UUID, etc).

The `App` field is optional, and may be used in any way you see fit. It is written on token creation. It may be used to specify which app requested the token, and apps may reject tokens not created by themselves, or allow. It's up to you.

The second part of the token after the `.` is an RSA signature of the first part. The signature is checked on token validation, and rejected for invalid signatures. Expiration is also strictly checked, and expired tokens rejected.

Revocation
----------

`uua` tokens can be revoked in any of the following ways. It is not currently possible to revoke a few, or single tokens. You may only revoke all current tokens

- Change the RSA signing key. Changing the signature will may all previous tokens invalid on signature checks. New tokens will validate fine
- Change the Encryption pass or salt. Either of these will force all previous tokens to fail decryption and therefore be invalid.
- Increment the `Generation`. By default, tokens are created in generation `1`. By increasing the generation (command line parameter), new tokens will be generation `2` (or whatever you set), and all generations `< 2` will be invalid. If the floor were set to `10`, then all generations 1 through 9 will be invalid. This is an easy way to invalidate tokens without having to change keys.