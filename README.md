Universal User Auth
=====================

`uua` is a Universal User Auth microservice. 

You provide it with a token request (login): username, secret (password, key, something else). And it responds with an encrypted+signed token. When the service is provided with a token, it validates the token and returns it's content (user, app, etc).

This is basically a [JWT](https://jwt.io/), or JWE flavor since it's encrypted, without the header. 

A token looks like this:

```
nNSmKIDSZl6tguSjz0buFpC/gowjIN1A6dPwkYoAVoekBVbvxUsGcR818nWDGeYUVaykA3Sr8fM+PwaL/y4m8OrOO/DpQNY+.JmezsGZb/zardmNWMub2tPU/ln2xtjYbhpEWcbzTQZ8EoxLWpcJ0IQGO5hEB1FEBz8k4ghKnsETZ0ozfFNoSOQv/yMGCUwtFpdK7KjYpWqxEgi/Kkt198uoXmJNQcm8y5eBkI4/FbbTBam0cbYQaSIGI6bjiFZ8Xhem5HzS/oTFWZT/uXzSGe4JGcO8BgoWRIEoXQY4Mcpzcl43Zgt3o+KH/U/QarIqNkFgIo2SpQR5qFIxovXkma05I/fOZ6YaxduXvAFQNjrSIImfNguGOb6aTqEr5un1YxMSSc9ojK/+vK+UolZSWO6H5QJ42+3fKuwsxkjit7BQ4yq5sGry7Rw==
```

It is dot (`.`) separated, like a JWT. The first section is `Base64(AES-256-GCM(JSON(content)))`. Where `content` is currently made up of the fields: 

- *Expiration*, time
- *User*
- *App*, which application requested the token
- *Version*, the UUA lib version
- *Generation*, your app version

The `User` field may be used to identify your own user in whatever way you see fit. Any string that uniquely identifies a user (email address, UUID, etc).

The `App` field is optional, and may be used in any way you see fit. It is written on token creation. It may be used to specify which app requested the token, and apps may reject tokens not created by themselves, or allow. It's up to you.

The second part of the token after the `.` is an RSA signature of the first part. The signature is checked on token validation, and rejected for invalid signatures. Expiration is also strictly checked, and expired tokens rejected.

Revocation
----------

`uua` tokens can be revoked in any of the following ways. It is not currently possible to revoke a few, or single tokens. You may only revoke all current tokens

- Change the RSA signing key. Changing the signature will may all previous tokens invalid on signature checks. New tokens will validate fine
- Change the Encryption pass or salt. Either of these will force all previous tokens to fail decryption and therefore be invalid.
- Increment the `Generation` floor. This uses the `Generation` field of the tokens. By default, tokens are created in generation `1`. By increasing the generation, new tokens will be generation `2`, and all generations `< 2` will be invalid. If the floor were set to `10`, then all generations 1 through 9 will be invalid. This is an easy way to invalidate tokens without having to change keys.