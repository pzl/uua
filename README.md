Universal User Auth
=====================

[![GoDoc](https://godoc.org/github.com/pzl/uua?status.svg)](http://godoc.org/github.com/pzl/uua)

`uua` is a Universal User Auth microservice. 

You provide it with a token request (login): username, secret (password, key, something else). And it responds with an encrypted+signed token. When the service is provided with a token, it validates the token and returns it's content (user, app, etc).

This is basically a [JWT](https://jwt.io/), or JWE flavor since it's encrypted, without the header. 

For using `uua` as a library, and not a microservice, see [As a Library](#as-a-library)

Quickstart
-----------

#### Create Users

```sh
echo "
auth:
  password:" > uua.yaml
echo "    some-user-name: " $(mkpass) >> uua.yaml # change to actual user's name, repeat for other users
```

(`mkpass` is a utility that comes with `uua`. It generates argon2-hashed passwords with a random salt.)

See [Set Authentication](#set-authentication)

#### Run

```sh
uua -c uua.yaml
```

#### Use

**Get Token**

```sh
curl -k -XPOST -d '{"user":"some-user-name", "pass":"yourpass"}' localhost:6089/api/v1/login
# {"token":"64vly..."}
```


**Auth with Token**

```sh
curl -k -XPOST -d "64vly..." localhost:6089/api/v1/verify
# {"token":{"v":1,"u":"some-user-name","g":1,"a":"","e":1560876042}, "valid":true }
```

see [Authenticating Users](#authenticating-users)



For the less-quick start, see [Integrating with Other Apps](#integrating-with-other-apps).


Recommended Configuration
--------------------------

### Use Static credentials

You can run `uua` with auto-generated credentials (RSA key, password+salt), but it will generate new ones each time it restarts. This invalidates all previous tokens, if even one of them is different. Using a temporary generated credential for any of these, only allows for tokens to be valid until the next restart.

This is OK for temporary situations. But for any sort of persistence beyond restarts, or load balancing between multiple `uua` servers, you need static credentials in your config.

**RSA Key**
```sh
ssh-keygen -t rsa -f sign.key # create a private RSA key
echo "sign-key: sign.key" >> uua.yaml
```

**Password & Salt**

```sh
echo "pass: abc123" >> uua.yaml
echo "salt: xyz456" >> uua.yaml
```

###  Enable SSL

**Generate self-signed cert & key**, (if you don't already have these from somewhere else, or are using Let's Encrypt, etc)

```sh
openssl req -x509 -nodes -newkey rsa:2048 -keyout server.key -out server.crt -days 3650
```

**Add to Config**

```sh
echo "
ssl-key: server.key
ssl-cert: server.crt
" >> uua.yaml
```

Then you can continue to run as normal: `uua -c uua.yaml`. and POST with:

```sh
curl -k -XPOST -d '{"user":"yourusername", "pass":"yourpass"}' https://localhost:6089/api/v1/login
```


Integrating with Other Apps
---------------------------

Because you probably want something to authenticate _to_. There are two methods of using UUA:

- [As an HTTP Microservice](#as-a-service)
- [As a Go Library](#as-a-library)

### As a Service

You can use UUA as an authentication microservice for your apps or microservices. 

1. Have your app prompt the user for username + password (until other auth methods are supported)
1. Your app will POST the credentials to `UUA:/api/v1/login`. `HTTP 401` on bad credentials, and a token otherwise
1. Associate and save the token with the user (somewhere safe, this token grants access as the user)
1. On next use, search that same place for a token
    + If no token, go back to step 1
    + POST to `UUA:/api/v1/verify` with the token as the body
    + if `401`, go back to step 1. Otherwise, you will receive username + some metadata. You can proceed as `user`

For more details on the HTTP endpoints see [Authenticating Users](#authenticating-users)


### As a Library

UUA provides an HTTP server, but it is not required. You may import and use `uua` as a golang library. Performing authentication is up to your app. the `uua` library's purpose is to:

- Create and serialize tokens
- Verify that a serialized token string is authentic, and valid

So your app must implement whatever authentication steps are required before granting a token to a user (user/pass, iris scan, device, etc).

**Creating a token**

```go
import "time"
import "github.com/pzl/uua"

const MY_APP = "demo"
const GENERATION = 1
const EXPIRATION = 3 * time.Hour

func main() {

    // secret material required to create tokens:
    // *rsa.PrivateKey (signing)
    // password + salt (symmetric encrypt token)
    key := loadPrivateKey() // *rsa.PrivateKey
    pass, salt := loadServerEnc()

    sec := uua.Secrets{
        Key:  key,
        Pass: pass,
        Salt: salt,
    }

    for {
        r := getRequest() // whatever user request or login your app has

        // validate credentials. This is up to your app to do. Check an email+pass perhaps
        if ! validCredentials(r) {
            respond(r, false, "bad credentials")
            continue
        }

        // create a token and serialize, encrypt, & sign it
        t, err := uua.New(r.Username, MY_APP, GENERATION, EXPIRATION).Encode(sec)
        if err != nil { //handle, log, whatever
            continue
        }

        respond(r, true, t) // send token string to the user, for storage
    }
}
```

**Validating a Token**

```go
package main

import "fmt"
import "github.com/pzl/uua"

const MY_APP = "demo"
const GENERATION = 1 // tokens must be of the same generation to be valid. Increment to revoke
// see Revocation at the bottom of the Readme for more info

func main() {
    // same secrets as above
    sec := uua.Secrets{
        Pass: pass,
        Salt: salt,
        Key:  key,
    }

    // with a user action, receive or read token string from somewhere
    ts := getTokenFromRequest() 

    token, err := uua.Validate(ts, sec, GENERATION)
    if err != nil { // invalid token (time expired, invalid signature, old generation)
        valid(false, err.Error())
        return
    }

    // valid `token` object. Can check token.App if desired to route a user someplace
    // or to make sure tokens used for some microservices are restricted to only those

    // optional
    if token.App != MY_APP {
        valid(false, fmt.Sprintf("tokens from %s are not valid at %s", token.App, MY_APP))
        return
    }

    valid(true, token.User) // allow access as this user
}

```

See [godoc](http://godoc.org/github.com/pzl/uua) for more

Config
-------

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

1. Command line arg (e.g. `-s mysalt56`)
1. Env var (e.g. `SALT=somesalt`)
1. Config file (via `-c FILEPATH`)  (supported extensions: `json, toml, yaml, yml` for all config files)
1. Config file (via `$CONFIG_FILE` env)
1. Config file (via default search paths)
1. Default values (generation and listen address have defaults)

The arguments are:

```
  -p, --pass     string   symmetric encryption password               ENV: PASS
  -s, --salt     string   symmetric encryption salt                   ENV: SALT
  -r, --rsa      string   RSA private key string for signing. Recommended to use a file instead.  ENV: RSA
  -k, --sign-key string   RSA private key file path, for signing      ENV: SIGN_KEY
  -y, --ssl-key  string   path to SSL private key                     ENV: SSL_KEY
  -t, --ssl-cert string   path to SSL certificate file                ENV: SSL_CERT
  -a, --addr     string   Server listening Address (default ":6089")  ENV: ADDR
  -g, --gen      uint     current token generation. Set to 0 to disable (default 1) ENV: GEN
  -j, --json              output logs in JSON formt                   ENV: JSON
  -c, --config   string   Config file to read values from             ENV: CONFIG
  -d, --conf-dir string   Search this directory for config files      ENV: CONF_DIR
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
json: true
auth:
  password:
    user1: b6b14ccd83113e4b267e2f0cd150fe2c53f35ae07dcfcdd1d49f4acb30ea681d.a877f3f295643388d873fe378338b9f4
    user: f082b78b194d2d2487bf0bc351a6eda4dacd244f0b51e27136b7d0e97ee24f44.59d52b113725090d812c2dcbaf6e4cb4

```

`uua -c conf.yaml` will start the server with these parameters. And `user1` and `user2` are the only valid users, identified by their respective passwords (which we don't know)

Set Authentication
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


Authenticating Users
----------------------

The `uua` server exposes two HTTP endpoints:

### Login

**`POST`  `/api/v1/login`**

expected body format: **json**

```js
{
    "user": "$USERNAME",
    "pass": "$PASSWORD",
    "app": "$APP_NAME", //optional
    "exp": 1800         //optional, expire time (in seconds)
}
```
Example:

```sh
curl -k -XPOST \
    -d '{"user":"bob", "pass":"carrots", "app": "calendar", "exp": 1800}' \
    https://localhost:6089/api/v1/login
```

**Responses**:

- Success: `HTTP 200`, `{"token": "64vl...."}`
- Failure: `HTTP 401`, `{"error":"invalid login"}`

### Verify

**`POST`  `/api/v1/verify`**

expected body: Token text

Example:

```sh
curl -k -XPOST \
    -d "64vlykYRouY5seenQ0XGs915WEwaC9UM5bzxitbf5Qb2HGkPTshV6ejErupi6kixNrwOuJjKhy2JivE52t/aWjfw5wHTfPMl6w==.EDYWMTl0i9xvQvoklDlSZfwBG0piSa0j8wmCKIDPtMpLGA1U4+pM68CYnZDFZ5++/ftPi++DOi+6BAEAPj3NlLnmu9c5FxkNbVgo0kzgCcIe5nu+uRVf1KYYI6puFmPvZF+zYpeJ+dq9f1X0PwUQexJFRMAj8qLwXXe2Wp9Dtre3HUkTQYJzHZ1y789JJAcx7RpDqTwEUpd0CqEudlw28BW5k6gME9yS7gtCHrZOqTo91iOFxoA9XFO4JA6HKTuc+KOzQqbTpOsE59gKTa17JBR6WzYR9NEXqpTp+UhpJP303cpv2Y/Z/L2gxAtyoJ5eDkUcQVIR2FaJsPMJbnL9qvVgrtW8rVjEqOHpQNqB4IQbV8XWH9euxmc87TUnIJVjjl4jrF/P8XsnVAYgnhWVfyWizaQU9+U5X5t80drY8T3sVWHZwIbagfr+sTMGzaDHvcLMdn4clExy5FcZG/UE393N/JTlVu8LN8N5xNEM/reDCO8SIufBw7eEUgIKkSeW" \
    https://localhost:6089/api/v1/verify
```

**Responses**:

- Success: `HTTP 200`, `{"valid":true, token":{"v":1,"u":"bob","g":1,"a":"calendar","e":1560876042}}`
- Failure: `HTTP 401`, `{"valid":false}`

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

- Change the RSA signing key. Changing the signature will make all previous tokens invalid on signature checks. New tokens will validate fine
- Change the Encryption pass or salt. Either of these will force all previous tokens to fail decryption and therefore be invalid.
- Increment the `Generation`. By default, tokens are created in generation `1`. By increasing the generation, new tokens will be generation `2` (or whatever you set), and all other generations `< 2` will be invalid. This is an easy way to invalidate tokens without having to change keys. If the floor were set to `10`, then all generations 1 through 9 will be invalid. "Future" generations will be valid. So `11+` will validate with a current Gen of `10`. This allows for perhaps selectively revoking tiers of tokens.   


License
---------

MIT 

Copyright (c) 2019 Dan Panzarella <dan@panzarel.la>

See [LICENSE](LICENSE) for full license