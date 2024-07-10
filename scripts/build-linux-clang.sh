#!/bin/bash

libedhoc_options="-DLIBEDHOC_ENABLE_UNIT_TESTS=ON -DLIBEDHOC_BUILD_COMPILER_CLANG=ON"
mbedtls_options="-DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF"

rm -rf build
mkdir build
cd build
cmake $libedhoc_options $mbedtls_options -G Ninja ..
ninja
