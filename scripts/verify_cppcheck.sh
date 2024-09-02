#!/bin/bash

cppcheck="cppcheck --enable=warning,style --inline-suppr"

library_dir="./library"
tests_source_dir="./tests/src"

echo "Cppcheck:"

# Verify library.
echo "- (lib)  API & source code."
$cppcheck $library_dir/*.c

# Verify module tests.
echo "- (test) module tests."
$cppcheck $tests_source_dir/*.c
