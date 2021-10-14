![Master](https://github.com/avast/authenticode-parser/actions/workflows/cmake.yml/badge.svg?branch=master)

# Authenticode parser
Authenticode-parser is a C library used to parse Microsoft digital signature format, that is being used to sign PE files on Windows systems.

The library interface takes binary data with Authenticode signature as input, which is then verified and parsed into an internal representation.

Features:
* Parsing of Authenticode signature - digests, signerInfo, certificates, building certificate chain
* Extracting further Nested Authenticode signature (through unauthenticated attributes)
* Parsing of PKCS9 timestamp counter-signatures
* Parsing of Microsoft timestamp counter-signatures
* Verification of the Authenticode signatures, PKCS9 and Microsoft timestamp counter-signatures (That hashes match, etc.)

Important note: Certificate chain is only built, but not verified as we cannot complete the verification without trust anchors anyway.

## Use of the library
Integrating the library is very easy through CMake. If you installed the library into a standard installation location of your system (e.g. `/usr`, `/usr/local`), all you need to do in order to use its components is:

```cmake
find_package(authenticode REQUIRED)

target_link_libraries(your-project
    PUBLIC 
        authenticode
      [...]
)
```

If your library is in different location, you can pass the path to your CMake `-Dauthenticode_DIR=<path>` or set a `CMAKE_PREFIX_PATH`.

A simple example of library use, that dumps all the parsed information, and integration can be found [here](https://github.com/avast/authenticode-parser/tree/master/examples).

## Build, Installation and Testing

### Requirements

* A C++ and a C compiler 
* [OpenSSL](https://www.openssl.org/) (version >= 1.1.1)
* [CMake](https://cmake.org/) (version >= 3.14)

On Debian-based distributions (e.g. Ubuntu), the required packages can be installed with `apt-get`:

```sh
sudo apt-get install build-essential cmake git openssl libssl-dev
```

On Windows, the required packages can be install with [Chocolatey](https://chocolatey.org/) - `choco`

```sh
choco install openssl cmake
```

On MacOS, the required packages can be install with `brew`

```sh
brew install openssl@1.1 cmake
```

### Build and Installation
* Clone the repository:
  * `git clone https://github.com/avast/authenticode-parser/`
* Linux and MacOS:
  * `cd authenticode-parser`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make install`
* Windows:
  * `cd authenticode-parser`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `cmake --build . --config Debug --target install`

If you wish to also build tests, pass `-DBUILD_TESTS=ON` option to CMake. For MacOS, if CMake can't find OpenSSL on PATH, you can pass it to the CMake with `-DOPENSSL_ROOT_DIR=/usr/local/opt/openssl` option

### Testing
Authenticode-parser is using [GoogleTest](https://github.com/google/googletest) as testing framework. Tests can be built using `-DBUILD_TESTS=ON` CMake option.

To run the tests go to the `build/` folder and run:
```sh
ctest -V
```

On Windows you will need to specify the configuration:
```sh
ctest -C Debug -V
```


## License

Copyright (c) 2021 Avast Software, licensed under the MIT license. See the LICENSE file for more details.
