Testing
=======

Overview
--------

libedhoc uses a 3-tier testing architecture to ensure correctness, robustness, and
protocol compliance:

1. **Unit tests** — Test individual functions and modules in isolation with mocked
   dependencies.
2. **Integration tests** — Exercise full EDHOC handshake flows and protocol message
   composition/processing against RFC test vectors.
3. **Fuzz tests** — LibFuzzer-based targets that stress message parsing and processing
   with random inputs.

Test Architecture
-----------------

Directory layout:

.. code-block:: text

   tests/
   ├── unit/           # Unit tests (topic subdirectories)
   │   ├── api/
   │   ├── cipher_suites/
   │   ├── coverage/
   │   │   ├── coverage_common.c
   │   │   ├── test_coverage_msg1.c
   │   │   ├── test_coverage_msg2.c
   │   │   ├── test_coverage_msg3.c
   │   │   ├── test_coverage_msg4.c
   │   │   ├── test_coverage_exporters.c
   │   │   ├── test_coverage_error.c
   │   │   ├── test_coverage_cbor.c
   │   │   └── test_coverage_handshake.c
   │   ├── internals/
   │   │   ├── internals_common.c
   │   │   ├── test_internals_common.c
   │   │   ├── test_internals_mac.c
   │   │   ├── test_internals_message2.c
   │   │   ├── test_internals_message3.c
   │   │   ├── test_internals_message4.c
   │   │   ├── test_internals_error.c
   │   │   ├── test_internals_message1.c
   │   │   ├── test_internals_helpers.c
   │   │   └── test_internals_api.c
   │   ├── exporters/
   │   ├── helpers/
   │   ├── message/
   │   ├── error/
   │   └── mem/
   ├── integration/    # Integration tests
   ├── common/         # Shared test helpers
   │   ├── include/
   │   └── src/
   ├── fuzz/           # LibFuzzer fuzz targets
   ├── test_main.c     # Test runner

Naming Convention
-----------------

**Files:** ``test_<subject>.c``

**TEST_GROUP:** Matches the file topic (e.g. ``test_coverage_msg1.c`` → ``TEST_GROUP(coverage_msg1)``)

**TEST cases:** Descriptive ``snake_case`` (e.g. ``TEST(coverage_msg1, compose_key_import_fail)``)

**Test groups by tier:**

Unit tests:
  - ``cipher_suite_0`` — EDHOC cipher suite 0 (EdDSA, ECDH, HKDF, AEAD, HASH)
  - ``cipher_suite_2`` — EDHOC cipher suite 2 (ECDSA via hash-then-sign, ECDH, HKDF, AEAD, HASH)
  - ``cipher_suite_24`` — EDHOC cipher suite 24 (ECDSA via hash-then-sign, ECDH, HKDF, AEAD, HASH)
  - ``api`` — EDHOC public API (context init, methods, cipher suites, bindings)
  - ``api_negative`` — Negative API tests (null args, invalid state, error paths)
  - ``error_message`` — EDHOC error message compose/process (success, unspecified, wrong suite, unknown cred)
  - ``exporters`` — PRK exporter, OSCORE session export, key update
  - ``helpers`` — Connection ID, flow prepend/extract, CoAP transport helpers
  - ``coverage_msg1`` … ``coverage_handshake`` — Mock-based failure injection split by message/topic
  - ``internals_common`` … ``internals_api`` — Internal function tests via ``STATIC`` / ``LIBEDHOC_MODULE_TESTS``
  - ``message_paths`` — Message composition/processing round-trips with real crypto

Integration tests:
  - ``rfc9529_chapter2`` — RFC 9529 Ch.2 vectors (signatures, x5t), message 1–4, handshake, EAD
  - ``rfc9529_chapter3`` — RFC 9529 Ch.3 vectors (static DH, kid), message 1–4, handshake
  - ``rfc9528_negotiation`` — Cipher suite negotiation (RFC 9528 Ch.6.3.2)
  - ``handshake_x5chain_sig_suite0`` — Full handshake, x5chain, signatures, suite 0
  - ``handshake_x5chain_sig_suite2`` — Full handshake, x5chain, signatures, suite 2
  - ``handshake_x5chain_sig_suite24`` — Full handshake, x5chain, signatures, suite 24
  - ``handshake_x5chain_dh_suite2`` — Full handshake, x5chain, static DH, suite 2
  - ``handshake_x5t_sig_suite2`` — Full handshake, x5t, signatures, suite 2
  - ``handshake_auth_methods`` — Handshake with auth methods 1 and 2

Fuzz targets:
  - ``fuzz_message_1_process`` — EDHOC message 1 processing
  - ``fuzz_message_2_process`` — EDHOC message 2 processing
  - ``fuzz_message_3_process`` — EDHOC message 3 processing
  - ``fuzz_message_4_process`` — EDHOC message 4 processing
  - ``fuzz_message_error_process`` — EDHOC error message processing

Test Documentation
------------------

Test case names use descriptive ``snake_case`` identifiers.  The ``TEST(group, name)``
macro pair should be readable without extra comment blocks.

Running Tests
-------------

The recommended entry point is the unified :file:`scripts/ci.sh` script.

**1. Build and run all tests**

.. code-block:: bash

   ./scripts/ci.sh build --gcc
   ./scripts/ci.sh test

**2. Run with coverage**

.. code-block:: bash

   ./scripts/ci.sh coverage
   # Or open report in browser:
   ./scripts/ci.sh coverage --open

**3. Run with sanitizers (ASan + UBSan) — GCC**

.. code-block:: bash

   ./scripts/ci.sh sanitizers asan-ubsan

**4. Run with Valgrind**

.. code-block:: bash

   ./scripts/ci.sh valgrind

**5. Run fuzzing — Clang only (LibFuzzer)**

Fuzzing uses Clang's built-in LibFuzzer; GCC does not ship an equivalent.

.. code-block:: bash

   ./scripts/ci.sh fuzz 60

**6. Run full CI pipeline locally**

.. code-block:: bash

   ./scripts/ci.sh all

Local Reproducibility
---------------------

To reproduce CI jobs locally, use the following commands:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - CI Job
     - Local Command
   * - GCC + Coverage
     - ``./scripts/ci.sh coverage``
   * - Clang
     - ``./scripts/ci.sh build --clang && ./scripts/ci.sh test``
   * - Sanitizers (asan-ubsan)
     - ``./scripts/ci.sh sanitizers asan-ubsan``
   * - Valgrind
     - ``./scripts/ci.sh build --gcc && ./scripts/ci.sh valgrind``
   * - Static Analysis
     - ``./scripts/ci.sh cppcheck && ./scripts/ci.sh clang-tidy``
   * - Fuzz
     - ``./scripts/ci.sh fuzz 60``
   * - Full pipeline
     - ``./scripts/ci.sh all``

Compiler selection
~~~~~~~~~~~~~~~~~~

The ``ci.sh`` script selects the compiler automatically based on the task:

.. list-table::
   :header-rows: 1
   :widths: 35 25 40

   * - Task
     - Compiler
     - Reason
   * - Build / tests / coverage
     - GCC
     - Default; ``gcov`` integration for coverage
   * - Clang build
     - Clang
     - Secondary compiler gate
   * - ASan + UBSan
     - GCC
     - Works with both; GCC chosen for consistency
   * - Fuzz
     - Clang
     - LibFuzzer is a Clang-only feature
   * - Static analysis
     - Clang
     - ``clang-tidy`` requires a Clang compile database
   * - Valgrind
     - GCC
     - Runtime tool; compiler independent

Coverage
--------

Coverage is measured with **gcov** (instrumentation) and **lcov** (report generation).
The build uses ``-DLIBEDHOC_ENABLE_COVERAGE=ON`` to add ``--coverage`` flags.

To generate coverage:

.. code-block:: bash

   ./scripts/ci.sh coverage
   # Report: build/coverage_html/index.html

Coverage excludes:

- ``externals/``
- ``tests/``
- ``backends/cbor/src/``
- ``/usr/*``

**Codecov.io** integration uploads coverage from CI. See :file:`codecov.yml` and the
``codecov/codecov-action`` step in :file:`.github/workflows/ci-linux.yml`.

Zephyr Benchmark (native_sim)
-----------------------------

A Zephyr benchmark app at ``sample/benchmark/`` runs a full EDHOC handshake
with cipher suite 2 (P-256/ES256) on ``native_sim``. This exercises all library
code paths, producing accurate flash footprint data and per-phase handshake
timing. Build and measure locally (requires west + Zephyr SDK):

.. code-block:: bash

   west build -b native_sim sample/benchmark -p always
   ./build/zephyr/zephyr.exe     # handshake timing (JSON on stdout)

   # Flash footprint by function (from final linked binary):
   nm --print-size --size-sort --defined-only build/zephyr/zephyr.exe \
     | grep -i edhoc | awk '{printf "%6d  %s\n", strtonum("0x"$2), $4}' | sort -rn

   # Total flash (single number):
   nm --print-size --size-sort --defined-only build/zephyr/zephyr.exe \
     | grep -i edhoc \
     | awk '{sum += strtonum("0x"$2)} END {printf "libedhoc flash: %d bytes (%.1f KiB)\n", sum, sum/1024}'

.. note::

   Zephyr's ``rom_report`` / ``ram_report`` targets require a fully-linked
   (non-relocatable) ELF. On ``native_sim`` the intermediate ``zephyr.elf`` is a
   partial link (``-r``), so those reports show most code as "(hidden)". The ``nm``
   analysis of the final ``zephyr.exe`` is authoritative instead.

The CI automatically builds this and uploads ``flash_report.txt`` and
``benchmark_timing.json`` as artifacts.
Expected library flash footprint is **~20 KiB** (0 bytes static RAM; with the
default stack backend all state lives on the stack).

Test Categories
---------------

Unit Tests
~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - File
     - Group
     - Description
   * - :file:`tests/unit/test_api.c`
     - ``api``
     - EDHOC public API: context init, methods, cipher suites, connection ID, bindings
   * - :file:`tests/unit/test_api_negative.c`
     - ``api_negative``
     - Negative tests: null pointers, invalid state, error paths for all API functions
   * - :file:`tests/unit/test_crypto_suite0.c`
     - ``crypto_suite0``
     - Cipher suite 0: EdDSA, ECDH, HKDF, AEAD, HASH
   * - :file:`tests/unit/test_crypto_suite2.c`
     - ``crypto_suite2``
     - Cipher suite 2: ECDSA, ECDH, HKDF, AEAD, HASH
   * - :file:`tests/unit/test_error_message.c`
     - ``error_message``
     - Error message compose/process: success, unspecified, wrong cipher suite, unknown cred
   * - :file:`tests/unit/test_exporters.c`
     - ``exporters``
     - PRK exporter, OSCORE session export, key update, error handling
   * - :file:`tests/unit/test_helpers.c`
     - ``helpers``
     - Connection ID equal/prepend/extract, flow prepend/extract, CoAP helpers
   * - :file:`tests/unit/test_coverage.c`
     - ``coverage``
     - Mock-based failure injection for deep internal error paths
   * - :file:`tests/unit/test_internals.c`
     - ``internals``
     - Internal function testing via ``STATIC`` / ``LIBEDHOC_MODULE_TESTS``
   * - :file:`tests/unit/test_message_paths.c`
     - ``message_paths``
     - Message composition/processing round-trips with real crypto

Integration Tests
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 35 25 40

   * - File
     - Group
     - Description
   * - :file:`tests/integration/test_rfc9529_chapter2.c`
     - ``rfc9529_chapter2``
     - RFC 9529 Ch.2: signatures, x5t; message 1–4, handshake, PRK exporter, EAD
   * - :file:`tests/integration/test_rfc9529_chapter3.c`
     - ``rfc9529_chapter3``
     - RFC 9529 Ch.3: static DH, kid; message 1–4, handshake
   * - :file:`tests/integration/test_rfc9528_negotiation.c`
     - ``rfc9528_negotiation``
     - RFC 9528 Ch.6.3.2: cipher suite negotiation (single/list)
   * - :file:`tests/integration/test_handshake_x5chain_sig_suite0.c`
     - ``handshake_x5chain_sig_suite0``
     - Full handshake, x5chain, signatures, suite 0; 1–2 certs in chain
   * - :file:`tests/integration/test_handshake_x5chain_sig_suite2.c`
     - ``handshake_x5chain_sig_suite2``
     - Full handshake, x5chain, signatures, suite 2; single/multiple EAD
   * - :file:`tests/integration/test_handshake_x5chain_dh_suite2.c`
     - ``handshake_x5chain_dh_suite2``
     - Full handshake, x5chain, static DH, suite 2; single EAD
   * - :file:`tests/integration/test_handshake_x5t_sig_suite2.c`
     - ``handshake_x5t_sig_suite2``
     - Full handshake, x5t, signatures, suite 2; cert hashes
   * - :file:`tests/integration/test_handshake_auth_methods.c`
     - ``handshake_auth_methods``
     - Handshake with auth methods 1 and 2

Fuzz Tests
~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Target
     - Description
   * - ``fuzz_message_1_process``
     - Fuzzes EDHOC message 1 processing
   * - ``fuzz_message_2_process``
     - Fuzzes EDHOC message 2 processing
   * - ``fuzz_message_3_process``
     - Fuzzes EDHOC message 3 processing
   * - ``fuzz_message_4_process``
     - Fuzzes EDHOC message 4 processing
   * - ``fuzz_message_error_process``
     - Fuzzes EDHOC error message processing

Static Analysis
---------------

**Cppcheck**

.. code-block:: bash

   ./scripts/ci.sh cppcheck

Runs cppcheck on :file:`library/` with ``--enable=warning,style`` and include paths for
:file:`include/`, :file:`helpers/include/`, ``backends/cbor/include/``.

**Clang-tidy**

.. code-block:: bash

   ./scripts/ci.sh clang-tidy

CI Integration
--------------

The GitHub Actions workflow :file:`.github/workflows/ci-linux.yml` runs:

- **GCC + Coverage** — GCC build with coverage, tests, lcov, Codecov upload
- **Clang** — Clang + Ninja build and tests
- **ASan + UBSan** — AddressSanitizer + UndefinedBehaviorSanitizer (GCC)
- **Valgrind** — Memcheck and DRD
- **Static Analysis** — cppcheck and clang-tidy
- **Fuzz** — LibFuzzer smoke test (60s per target, Clang)
- **Benchmark** — Binary size analysis and handshake timing (Release, GCC)

The unified :file:`scripts/ci.sh` script can replicate most of this locally with
``./scripts/ci.sh all``.

