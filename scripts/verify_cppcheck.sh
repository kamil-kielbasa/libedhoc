#!/bin/bash

cppcheck="cppcheck --enable=warning,style --inline-suppr"

library_dir="./library"
tests_source_dir="./tests/src"

echo "Cppcheck:"

# Format libedhoc.
echo "- (lib)  libedhoc."
$cppcheck $library_dir/*.c

# Format tests: cipher suite negotiation.
echo "- (test) cipher suite negotiation."
path="cipher_suite_negotiation"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: cipher suites.
echo "- (test) cipher suites."
path="cipher_suites"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: edhoc trace 1.
echo "- (test) edhoc trace 1."
path="edhoc_trace_1"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: edhoc trace 2.
echo "- (test) edhoc trace 2."
path="edhoc_trace_2"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: error message.
echo "- (test) error message."
path="error_message"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: X.509 chain over cipher suite 0.
echo "- (test) X.509 chain over cipher suite 0."
path="x509_chain_cs_0"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: X.509 chain over cipher suite 2.
echo "- (test) X.509 chain over cipher suite 2."
path="x509_chain_cs_2"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: X.509 hash over cipher suite 2.
echo "- (test) X.509 hash over cipher suite 2."
path="x509_hash_cs_2"
$cppcheck $tests_source_dir/$path/*.c

# Format tests: entry point.
echo "- (test) entry point."
$cppcheck $tests_source_dir/*.c
