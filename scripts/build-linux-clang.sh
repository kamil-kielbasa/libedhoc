#!/bin/bash

libedhoc_options+="-DLIBEDHOC_ENABLE_MODULE_TESTS=ON "
libedhoc_options+="-DLIBEDHOC_BUILD_COMPILER_CLANG=ON "

mbedtls_options+="-DENABLE_PROGRAMS=OFF "
mbedtls_options+="-DENABLE_TESTING=OFF "

kconfig_options+="-DCONFIG_LIBEDHOC_ENABLE=1 "
kconfig_options+="-DCONFIG_LIBEDHOC_KEY_ID_LEN=4 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=3 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY=32 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_LEN_OF_MAC=32 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=3 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=1 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=1 "
kconfig_options+="-DCONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=2 "
kconfig_options+="-DCONFIG_LIBEDHOC_LOG_LEVEL=4 "

rm -rf build
mkdir build
cd build
cmake $libedhoc_options $mbedtls_options $kconfig_options-G Ninja ..
ninja
