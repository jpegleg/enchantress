![cdlogo](https://carefuldata.com/images/cdlogo.png)

# Enchantress

Enchantress is a tool for AES-256 encryption in CTR mode.

In addition to AES-256 CTR, there is also an integrity checking mechanism with SHA3.

With the integrity check added, the behavior is much more like AES-GCM, except that instead of GMAC, we have SHA3 hash comparisons.
This implementation is more simple than GMAC (GCM), yet provides a more flexible and easy to understand integrity and authentication system.

Encryptions are are recorded in an `enchantress.toml` which is needed for decryption.

The key is generated based on a password processed in Argon2:

```
Argon2 round 1: supplied password + fixed1 ->
  Argon2 round2: result of round 1 + fixed2 ->
    actual key material

```

This is an "overkill" amount of Argon2, as 1 round of Argon2 is already plenty, assuming you have at least 19MB of RAM.

The AES-256 uses that final key material and an NONCE IV that has time data and random data from the system.

As of v0.1.3: The output of enchantress is JSON, except for when decrypting to STDOUT. Errors also print JSON.
Password prompts use STDERR as to avoid messing with redirection, so we can still redirect and pipe the JSON when supplying a password interactively.

As of v0.1.4: Enchantress functions are also available as a library and can be imported into your project from crates.io.

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

## Project promises

This project will never use AI-slop. All code is reviewed, tested, implemented by a human that is academically trained in cryptography and information security.
This repository and the crates.io repository is carefully managed and protected.

This project will never break backwards compatibility with decryption.

This project will be maintained as best as is reasonable.

## Ciphertext integrity

AES-256 CTR mode does not provide non-malleability, so SHA3 and a serialized config file with hash comparison logic are used to provide an additional layer of non-malleability.
This helps ensure that ciphertext files are not tampered with. If the ciphertext or password are not correct, enchantress will print a message like so and exit:

```
{
  "ERROR": "Ciphertext and/or password are not as expected. The supplied password was wrong, the enchantress.toml was wrong, or the file was tampered with.",
  "Found hash": "zHuCjbtVtgUj/osukIU7Lfa/MuJXvOWsTwbyRdIb2sM7AvM7dE3JBlm4J+qIvjP6xnlarb/cgKgslbfsqPOGLw==",
  "Expected hash": "mX7aiGz8k2w7AXItnwNttL03xHed/dm1wZX/hi22DZcEqbpeBhMgeAKuxuJgOF1TJDFd3FoqlrNrLqcLCW0YWg==",
  "Result": "Refusing to decrypt."
}
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
{"Validation string": "mX7aiGz8k2w7AXItnwNttL03xHed/dm1wZX/hi22DZcEqbpeBhMgeAKuxuJgOF1TJDFd3FoqlrNrLqcLCW0YWg=="}
enchantress /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
cd ..
cd data_2
enchantress /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
{"Validation string": "7xzFsmth88L9YZwpHqUMBbNdx9IVHtAneshyDSqXi6IcT6SL9r8SxE6DjKg/bpzQargpfmo1/fzeKSA6Ve5QDg=="}
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
{"Validation string": "fDtQiBLuMFZeebE7WmOkgHXbxHAbgbTUEEsx2fH2p8ZkR0LVTluzzwuYKVjobLLHyNUB50cMF57ftQPNcRyyYg=="}
enchantress /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
mv enchantress.toml myfile_enchantress.toml
enchantress /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
{"Validation string": "BS40KBN66tTCs7GDBIThqT2UyJBR+bJhekUbkl8PfIvfrusk+0FkRohrAGcatBjwYM4GIyBOVvDY4FiKePjMfw=="}
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
{"Validation string": "/eOzNTiB/htZxl8DhdYzWkyw/WuDMERU6To09r85X72JWDalObKrBI88UkhSzBy1o1RT2h+lpurf7vtxn0MaSw=="}
```

When we decrypt files, we can either print to STDOUT or decrypt to a file. If the data is binary, then printing to STDOUT is not very useful and likely you should decrypt to a file.
If the data is text that needs to stay protected, they decrypting to STDOUT is useful as to not expose the plaintext to the disk and need to remove it again.

There are also options for using the environment variable "ENC". This is generally less secure, but provides a way for automation to utilize enchantress.
We can set a password as an environment variable so that systems that need to automatically encrypt can do so without an interactive prompt or exposed key file on the disk.

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchantress /someplace/myfile /someplace/myfile.e -ee
{"Validation string": "/eOzNTiB/htZxl8DhdYzWkyw/WuDMERU6To09r85X72JWDalObKrBI88UkhSzBy1o1RT2h+lpurf7vtxn0MaSw=="}
rm -f /someplace/myfile
```

Then to decrypt with the "ENC" environment variable:

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchantress /someplace/myfile.e /someplace/myfile -de
{"Result": "file decrypted"}
```

If we want to clear out the environment variable (in BASH), we can 'unset' it:

```
unset ENC
```

Fun fact: emojis can be used in passwords in most cases and can create very strong passwords in some cases.


## Using enchantress as a library

While enchantress is a tool, the functions are also exposed as a library as of v0.1.4.

We can add enchantress to another Rust project with:

```
cargo add enchantress
```

Or by adding the desired version to the Cargo.toml.

Once imported, the features of enchantress can be recreated or utilzied within another program.

Here is a simple demo example with no integrity checking, adding file encryption using enchantress functions for key material generation and AES-CTR:

```
use enchantress::*;

fn main() {
    println!("this is just a demo!");
    let key = a2(b"hard coded password bad", MAGIC);
    let _ = encrypt_file("Cargo.toml", "Cargo.toml.e", &key);
}

```

The enchantress tool doesn't use hard-coded passwords but rather user provided interactive password or password from environment variable.

This is what it would looke like to re-implement the same functionality as used in enchantress for interactive password based encryption:

```

            eprint!("Enter password: ");
            std::io::stdout().flush()?;
            let password = read_password()?;
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, MAGIC);
            encrypt_file(input_file, output_file, &key)?;
            let mut out_file = File::open(output_file)?;
            let mut output_file_data = Vec::new();
            out_file.read_to_end(&mut output_file_data)?;
            let validate = ciphertext_hash(&key, &output_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            println!("{{\"Validation string\": \"{validate_str}\"}}");
            key.zeroize();
```

The main difference from that example and the actual code in enchantress, other than the error handling and import style, is that this example doesn't write out an `enchantress.toml`.

This example shows the full combination of key material generation, encryption, and validation string generation.

Then when we go to decrypt, enchantress handles it like this. Agaain, the error handling and module naming is different than code used in the enchantress tool.
The error handling and JSON format is removed in this example to improve clarity. Check out the source code for enchantress to see more on that subject.

```
            eprint!("Enter password: ");
            std::io::stdout().flush()?;
            let password = read_password()?;
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, MAGIC);
            let mut in_file = File::open(input_file)?;
            let mut input_file_data = Vec::new();
            in_file.read_to_end(&mut input_file_data)?;
            let validate = ciphertext_hash(&key, &input_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            let checkme = &validate_str;
            if checks(checkme, &config.ciphertext_hash) == true {
              decrypt_file(input_file, output_file, &key)?;
              println!("file decrypted");
            } else {
              println!("refusing to decrypt");
            };
            key.zeroize();
```

In both of these examples we use `eprint!` macro to print to STDERR for the password prompts. This is useful for when the tool STDOUT is used to write to another file or log so that
the password prompt isn't added to the output file/s.

The enchantress tool reads the `enchantress.toml` to find the ciphertext_hash (the string created from the encryption, the "Validation string" from the example). That value could be
set another way, but the implementation should be carefully enforced if the integrity checking matters. Of course other layers like HMAC and GMAC (GCM) can be implemented in addition or instead.

Enchantress uses [zeroize](https://docs.rs/zeroize/latest/zeroize/) to explicitly empty the key from memory. This technique is generally recommended to avoid the edge case where the compiler optimizes away an important aspect of "zeroizing" a value.


