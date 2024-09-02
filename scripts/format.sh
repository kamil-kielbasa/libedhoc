#!/bin/bash

include_dir="./include"
library_dir="./library"
tests_include_dir="./tests/include"
tests_source_dir="./tests/src"

echo "Formating:"

# Format libedhoc.
echo "- (lib)  API & source code."
clang-format -i $include_dir/*.h
clang-format -i $library_dir/*.c

# Format tests: entry point.
echo "- (test) module tests."
clang-format -i $tests_include_dir/*.h
clang-format -i $tests_source_dir/*.c
