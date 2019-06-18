Universal User Auth
=====================

`uua` is a Universal User Auth microservice. 

You provide it with a token request (login): username, secret (password, key, something else). And it responds with an encrypted+signed token. When the service is provided with a token, it validates the token and returns it's content (user, app, etc).

This is basically a [JWT](https://jwt.io/), or JWE flavor since it's encrypted, without the header. 


Usage
------

**Prerequisites**:

- Generate RSA key for signing tokens: `ssh-keygen -t rsa -f signing_rsa`
- Have or generate `server.crt` and `server.key` for SSL (use `make key` to make quick test certs)

---

**Simple Use**:

```sh
uua -p somepass -s mysalt -k private_rsa
```

to avoid specifying credentials on the command line, you can use ENV vars, or a config file:

```sh
echo "
sign-key: private_rsa
pass: encpass
salt: x3*h9dw0e
" > config.yml # create a config file
CONFIG_FILE=config.yml uua  # or -c config.yml
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
  -p, --pass     string   symmetric encryption password               ENV: PASS
  -s, --salt     string   symmetric encryption salt                   ENV: SALT
  -r, --rsa     string    RSA private key string for signing. Recommended to use a file instead.  ENV: RSA
  -k, --sign-key string   RSA private key file path, for signing      ENV: SIGN_KEY
  -a, --addr     string   Server listening Address (default ":6089")  ENV: ADDR
  -g, --gen     uint      current token generation. Set to 0 to disable (default 1) ENV: GEN
  -c, --conf     string   Config file to read values from             ENV: CONFIG_FILE
```


The required parameters (via any method above) are: **pass**, **salt**, and an RSA key, _either_ through **rsa** or **sign-key**. 

The key names for these properties match their `--long` flag names. I.e. `--pass` will be `pass: x`

Example full config file:

```yaml
pass: y0urT0kenEncr7ptn
salt: aRandomSaltValue
sign-key: /path/to/your/signing/rsa.key
ssl-key:  /path/to/SSL/private.key
ssl-cert: /path/to/signed/server.crt
addr: :443
gen: 6
auth:
  password:
    user1: b6b14ccd83113e4b267e2f0cd150fe2c53f35ae07dcfcdd1d49f4acb30ea681d.a877f3f295643388d873fe378338b9f4
    user: f082b78b194d2d2487bf0bc351a6eda4dacd244f0b51e27136b7d0e97ee24f44.59d52b113725090d812c2dcbaf6e4cb4

```

`uua -c conf.yaml` will start the server with these parameters. And `user1` and `user2` are the only valid users, identified by their respective passwords (which we don't know)

Authenticating Users
---------------------

Right now the only authentication method is username:password combo. More methods are planned to be added in the future.

### Passwords

Users are created by adding an entry to the config file (examples below). Passwords are _never_ stored. Only the [Argon2](https://en.wikipedia.org/wiki/Argon2) hash, and salt. The user's password cannot be recovered from this information. Generating the hash and salt to insert into the config file can be done with the included `mkpass` utility. run `./bin/mkpass` and it will prompt for a password. Hit `Enter` and a `hash.salt` will be printed out. This can then be entered into the conf file with the desired username.

Examples:  
yaml
```yaml
# YAML ...
auth:
    password:
        alice: 5911c1e671a5c66d2335d2a704b9844ad3376adcca8e2de194e161e5fbf283ee.adae8cdd7ea456dad56483ce3303ce14
        bob: 9edd51a088332778885b8743be3859bd847bf5399978717988e437380ec5e315.a6e95c4049c218cae9e047428d526872
```
json
```json
{
  "auth": {
    "password": {
      "alice":"5911c1e671a5c66d2335d2a704b9844ad3376adcca8e2de194e161e5fbf283ee.adae8cdd7ea456dad56483ce3303ce14",
      "bob":"9edd51a088332778885b8743be3859bd847bf5399978717988e437380ec5e315.a6e95c4049c218cae9e047428d526872"
    }
  }
}

```
toml
```toml
[auth]
  [auth.password]
    bob = "9edd51a088332778885b8743be3859bd847bf5399978717988e437380ec5e315.a6e95c4049c218cae9e047428d526872"
    alice = "5911c1e671a5c66d2335d2a704b9844ad3376adcca8e2de194e161e5fbf283ee.adae8cdd7ea456dad56483ce3303ce14"
```


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
