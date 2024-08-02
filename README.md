# Argon2

Command-line wrapper utility for argon2 library.

By default, it disables command-prompt input echoing by default and generates a variable size hash based on a specified salt and input.

If argon2 library is not system-wide available, build process bootstraps argon2 library.

### Build
```
cmake -B build
cmake --build build
./build/argon2 -h
```
