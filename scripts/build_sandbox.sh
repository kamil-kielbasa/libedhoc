#!/bin/bash

set -e

BASEDIR=$(pwd)
BUILD_DIR=$(pwd)/build/sandbox/build
INSTALL_DIR=$(pwd)/build/sandbox/install
mkdir -p $BUILD_DIR $INSTALL_DIR


echo \#### Configure zcbor \####
cmake -S $BASEDIR/externals/zcbor-cmake -B $BUILD_DIR/zcbor \
    -DZCBOR_PATH=$BASEDIR/externals/zcbor \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
    -GNinja
echo \#### Build and install zcbor \####
cmake --build $BUILD_DIR/zcbor --target install


echo \#### Configure mbedtls \####
cmake -S $BASEDIR/externals/mbedtls -B $BUILD_DIR/externals/mbedtls \
    -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
    -GNinja
echo \#### Build and install mbedtls \####
cmake --build $BUILD_DIR/externals/mbedtls --target install


echo \#### Configure libedhoc \####
cmake -B $BUILD_DIR/libedhoc \
    -DCONFIG_LIBEDHOC_ENABLE=ON \
    -DCONFIG_LIBEDHOC_KEY_ID_LEN=4 \
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7 \
    -DCONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=1 \
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY=32 \
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_MAC=32 \
    -DCONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=0 \
    -DCONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=1 \
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=0 \
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=1 \
    -DCONFIG_LIBEDHOC_LOG_LEVEL=4 \
    -DLIBEDHOC_BUILD_EXTERNAL_DEPS=OFF \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
    -GNinja
echo \#### Build and install libedhoc \####
cmake --build $BUILD_DIR/libedhoc --target install
