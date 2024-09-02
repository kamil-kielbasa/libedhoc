#!/bin/bash

libedhoc_options="-DLIBEDHOC_ENABLE_MODULE_TESTS=ON -DLIBEDHOC_ENABLE_MODULE_TESTS_TRACES=OFF -DLIBEDHOC_BUILD_COMPILER_GCC=ON"
mbedtls_options="-DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF"

rm -rf build
mkdir build
cd build
cmake $libedhoc_options $mbedtls_options -DCMAKE_BUILD_TYPE=Debug ..
make -j
