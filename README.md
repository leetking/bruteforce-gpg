# bruteforce-gpg

This is a tool used to recover the passphrase of a GPG secret (a.k.a private) key.

## Usage

```
bruteforce-gpg [-h] [-v] [-t NUM_THREADS] -f WORDLIST GPG_SECRET_KEY
```

## Setup
### 1. Install Dependencies

This tool depends on the [libgpgme](https://www.gnupg.org/software/gpgme/index.html) library and [pkg-config](http://pkg-config.freedesktop.org) tool.

On Kali
```bash
$ sudo apt install libgpgme-dev pkg-config
```

On Arch Linux
```bash
$ sudo pacman -S gpgme pkg-config
```

### 2. Download

```bash
$ git clone https://github.com/mathewmarcus/bruteforce-gpg.git
```

### 3. Build

```bash
$ cd bruteforce-gpg
$ make
```

### 4. Install

`bruteforce-gpg` will be installed in the `/usr/local/bin/` directory, so you may want to ensure it is included in your `PATH` environment variable.

```bash
# make install
```

## Examples
With the default (i.e. 1) threads

```bash
$ bruteforce-gpg -f /usr/share/wordlists/rockyou.txt private_key.asc
```

With 8 threads

```bash
$ bruteforce-gpg -t 8 -f /usr/share/wordlists/rockyou.txt private_key.asc
```
