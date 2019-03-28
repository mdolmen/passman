Password Manager
================

___Do not use this as your main password manager.___

This is a learning project to practice secure coding and manipulation of
cryptography library.

Requirements
------------

- `nacl` and `nacl-devel` (Fedora package name, may vary depending on your
  distro)
- `check` and `check-devel` : unit testing

Build
-----

```bash
make
bin/passman
```

Run tests
---------

```bash
make test
tests/test
```

Clean up
--------

```bash
make clean
```
