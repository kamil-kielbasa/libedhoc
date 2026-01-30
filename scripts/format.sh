#!/bin/bash

include_dir="./include"
library_dir="./library"
helpers_include_dir="./helpers/include"
helpers_source_dir="./helpers/src"
tests_include_dir="./tests/include"
tests_source_dir="./tests/src"
port_dir="./port"

echo "Formating:"

# Format libedhoc.
echo "- (lib)     API & source code."
clang-format -i $include_dir/*.h
clang-format -i $library_dir/*.c

# Format helpers.
echo "- (helpers) helper module."
clang-format -i $helpers_include_dir/*.h
clang-format -i $helpers_source_dir/*.c

# Format tests: entry point.
echo "- (test)    module tests."
clang-format -i $tests_include_dir/*.h
clang-format -i $tests_source_dir/*.c

# Format port: log backend for Zephyr.
echo "- (port)    log backend for Zephyr."
clang-format -i $port_dir/log/zephyr/edhoc_log_backend.h
clang-format -i $port_dir/log/zephyr/edhoc_log_backend.c

# Format port: log backend for Linux.
echo "- (port)    log backend for Linux."
clang-format -i $port_dir/log/linux/edhoc_log_backend.h

# Format port: log backend for Zephyr.
echo "- (port)    log backend for Zephyr."
clang-format -i $port_dir/log/zephyr/edhoc_log_backend.h
clang-format -i $port_dir/log/zephyr/edhoc_log_backend.c
