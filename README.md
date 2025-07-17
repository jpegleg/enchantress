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

This is an "overkill" amount of Argon2, as 1 round of Argon2 is already plenty, assuming you have at least 19MB of RAM.

The AES-256 uses that final key material and a nonce that has time data and random data from the system.

## Installing

Enchantress can be installed from crates.io:

```
cargo install enchantress
```

Or compiled from source:

```
cargo build --release
sudo cp target/release/enchantress /usr/local/bin/
```

Or installed from a release binary.


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
This helps ensure that ciphertext files are not tampered with. If the ciphertext or password are not correct, enchantress will print a message like so and exit:

```
Ciphertext and/or password are not as expected. The supplied password was wrong, the enchantress.toml was wrong, or the file was tampered with.
Found hash: wcUIBjCNaWdH6ljwqSgiHSMqRzCBM6yEFvGeiqqzkYsgLUbJcNyEbdMuZNqfFlDxMbxD1nqfcrmWBvRdxuzAGw==
Expected hash: zRLHXuhOh5UMIRN4wbXks9u43DZ8HdQXjiCOznrK2yaPsMjzFnSvJWMSIh/w1Vv5g05J5lC7XHi4t2glzEKW3g==
Refusing to decrypt.
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

The only line actually required for decryption is the ciphertext_hash, the other lines are for human use.
An enchantress.toml can be created/recreated manually. The "validation string" that the encryption outputs
is ciphertext_hash, and can be stored separately or shared, etc etc.

The password used is the secret to protect. The password is not stored and explicitly emptied from memory.

Weak passwords are weak security. Enchantress does not enforce "good" passwords, password security is up to you!

## Usage patterns

Becaue there can only be one `enchantress.toml` in the working directory, when working with multiple files we might either change directories or move the enchantress.toml files that are created to other names.

Here is an example of creating directories and then moving into them to encrypt each file.
In this example we also validate that the decryption is working before removing the plaintext.

```
mkdir data_1 data_2
cd data_1
enchantress /someplace/myfile /someplace/myfile.e -e
Enter password:
Validation string is: zRLHXuhOh5UMIRN4wbXks9u43DZ8HdQXjiCOznrK2yaPsMjzFnSvJWMSIh/w1Vv5g05J5lC7XHi4t2glzEKW3g==
enchantress /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
cd ..
cd data_2
enchantress /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
Validation string is: OxEJKQfc3ilJGD0DOZ/nLzsHOBOPZf8SIqnd1/G+EfIiBVdFtZJs0DrURohf9HX++waeqs4qrnSKB1w/rm+3+g==
enchantress /someplace/anotherfile.e . -do
Enter password:
some other data
rm -f /someplace/anotherfile
cd ..
```

In this example we stay in the same directory, but move the enchantress.toml file to new file names after each encryption.

```
enchantress /someplace/myfile /someplace/myfile.e -e
Enter password:
Validation string is: zRLHXuhOh5UMIRN4wbXks9u43DZ8HdQXjiCOznrK2yaPsMjzFnSvJWMSIh/w1Vv5g05J5lC7XHi4t2glzEKW3g==
enchantress /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
mv enchantress.toml myfile_enchantress.toml
enchantress /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
Validation string is: OxEJKQfc3ilJGD0DOZ/nLzsHOBOPZf8SIqnd1/G+EfIiBVdFtZJs0DrURohf9HX++waeqs4qrnSKB1w/rm+3+g==
enchantress /someplace/anotherfile.e . -do
Enter password:
some other data
rm -f /someplace/anotherfile
mv enchantress.toml anotherfile_enchantress.toml
```

When moving the enchantress.toml to new file names, we'll have to move them back to enchantress.toml to decrypt.

Notice how in these examples we have "." as the output file when using the "-do" option. The value of the output file can be anything when the decryption is going to STDOUT
because it is not written, so a period or any other single character is one way to do it.

Another technique is to use the same file for both input and output. This is not generally recommended as you don't have a chance to validate the decryption and the file name isn't changed.
But it is an option that can be used.

```
enchantress /someplace/myfile /someplace/myfile -e
Enter password:
Validation string is: zRLHXuhOh5UMIRN4wbXks9u43DZ8HdQXjiCOznrK2yaPsMjzFnSvJWMSIh/w1Vv5g05J5lC7XHi4t2glzEKW3g==
```

When we decrypt files, we can either print to STDOUT or decrypt to a file. If the data is binary, then printing to STDOUT is not very useful and likely you should decrypt to a file.
If the data is text that needs to stay protected, they decrypting to STDOUT is useful as to not expose the plaintext to the disk and need to remove it again.

There are also options for using the environment variable "ENC". This is generally less secure, but provides a way for automation to utilize enchantress.
We can set a password as an environment variable so that systems that need to automatically encrypt can do so without an interactive prompt or exposed key file on the disk.

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchantress /someplace/myfile /someplace/myfile.e -ee
Validation string is: mP3dNHQUpnL7420BWdJdKqY4plQBZDZft8A6wnTTV1dJaeWSz8AdSiwfu8uTilnogORHtOda/sHzkyV/2BAtyw==
rm -f /someplace/myfile
```

Then to decrypt with the "ENC" environment variable:

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchantress /someplace/myfile.e /someplace/myfile -de
```

If we want to clear out the environment variable (in BASH), we can 'unset' it

```
unset ENC
``
