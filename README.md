![cdlogo](https://carefuldata.com/images/cdlogo.png)

# Enchantress

Enchantress is a tool for AES-256 encryption in CTR mode.

In addition to AES-256 CTR, there is also an integrity checking mechanism with SHA3.

Encryptions are are recorded in an `enchantress.toml` which is needed for decryption.

The key is generated based on a password processed in Argon2:

```
Argon2 round 1: supplied password + fixed1 ->
  Argon2 round2: result of round 1 + fixed2 ->
    actual key material

```

This is an "overkill" amount of Argon2, as 1 round of Argon2 is already plenty.

The AES-256 uses that final key material and a nonce that has time data and random data from the system.

## Installing


## Command options

There are two different modes and two types of decryption. 

```
The first mode is with a supplied password interactively supplied in the terminal: -e and -d
The second mode is with a password set as the environment variable "ENC": -ee and -de
The two types of decryption are:
  decryption to a file: -d and -de
  decryption to STDOUT: -do and -deo
```
  
## Ciphertext integrity

AES-256 CTR mode does not provide non-malleability, so SHA3 and a serialized config file with hash comparison logic are used to provide an additional layer of non-malleability.
This ensure that ciphertext files are not tampered with. If the ciphertext or password are not correct, enchantress will panic like so:

```
thread 'main' panicked at src/main.rs:50:4:
assertion `left == right` failed
  left: "w3E3Lx5gZZjJpzV7GAzNqx5g5y5QHDiojhaThRGrUASif+lX2o1SmNhvCbGdmaGW8sYLxmTQ4MQnaYx/XBMubA=="
 right: "xshPOXhtqGJtBoIj/vvxWSh55hryEOMYRqOeedH0hJJccH/edQSUqXxkGvvaFNeJfL9NOaAVUdav4z1tAkn+/A=="
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

This integrity check is a comparison of base64 encoded SHA3 64 byte XOFs. The hashes are constructed from the ciphertext and the key material being processed together, output as a 64 byte SHA3 XOF.

## The enchantress.toml file

With each encryption, an `enchantress.toml` file is created in the pwd of the command execution. 

<b>WARNING: This file will be overwritten if one is already present and an encryption is run in the same directory!</b>

The config file contains the ciphertext path, the validation hash, and the time of the encryption.

Example:
```
ciphertext_path = "my_data.e"
ciphertext_hash = "xshPOXhtqGJtBoIj/vvxWSh55hryEOMYRqOeedH0hJJccH/edQSUqXxkGvvaFNeJfL9NOaAVUdav4z1tAkn+/A=="
creation_time = "2025-07-13 19:15:32.334352329 UTC"
```

The `ciphertext_hash` is not a secret itself and can be safely shared.

The password used is the secret to protect. The password is not stored and explicitly emptied from memory.
