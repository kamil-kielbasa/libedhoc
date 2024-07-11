#!/bin/bash

include_dir="./include"
library_dir="./library"
tests_include_dir="./tests/include"
tests_source_dir="./tests/src"

echo "Formating:"

# Format libedhoc.
echo "- (lib)  libedhoc."
clang-format -i $include_dir/*.h
clang-format -i $library_dir/*.c

# Format tests: cipher suite negotiation.
echo "- (test) cipher suite negotiation."
path="cipher_suite_negotiation"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: cipher suites.
echo "- (test) cipher suites."
path="cipher_suites"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: edhoc trace 1.
echo "- (test) edhoc trace 1."
path="edhoc_trace_1"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: edhoc trace 2.
echo "- (test) edhoc trace 2."
path="edhoc_trace_2"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: error message.
echo "- (test) error message."
path="error_message"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: X.509 chain over cipher suite 0.
echo "- (test) X.509 chain over cipher suite 0."
path="x509_chain_cs_0"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: X.509 chain over cipher suite 2.
echo "- (test) X.509 chain over cipher suite 2."
path="x509_chain_cs_2"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

echo "- (test) X.509 chain over cipher suite 2 with static DH keys."
path="x509_chain_cs_2_static_dh"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: X.509 hash over cipher suite 2.
echo "- (test) X.509 hash over cipher suite 2."
path="x509_hash_cs_2"
clang-format -i $tests_include_dir/$path/*.h
clang-format -i $tests_source_dir/$path/*.c

# Format tests: entry point.
echo "- (test) entry point."
clang-format -i $tests_source_dir/*.c
