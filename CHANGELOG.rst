Version 1.5.0
-------------

:Date: February 27, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CI/CD pipeline overhaul:

  * Renamed and unified GitHub Actions workflow files (``ci-linux.yml``, ``ci-zephyr.yml``, ``ci-sandbox.yml``, ``ci-docs.yml``).
  * Consolidated all CI jobs into a single ``scripts/ci.sh`` entry point.
  * Removed redundant standalone scripts (``build-linux-gcc.sh``, ``build-linux-clang.sh``, ``coverage.sh``, ``verify_cppcheck.sh``, ``format.sh``).
  * Added weekly scheduled CI workflow (``ci-weekly.yml``) running all jobs including extended fuzzing.
  * Split sanitizer CI jobs: ASan+UBSan (GCC) runs separately.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Compiler flags hardening:

  * Unified GCC and Clang warning flags into a shared ``LIBEDHOC_COMMON_WARNINGS`` set (~25 flags).
  * Added GCC-specific flags: ``-Wformat-overflow=2``, ``-Wformat-truncation=2``, ``-Wswitch-enum``, ``-Wjump-misses-init``, ``-Wduplicated-cond``, ``-Wduplicated-branches``, ``-Wlogical-op``.
  * Added ``-fstack-protector-strong`` (disabled under sanitizers).
  * Made ``-Wno-unsafe-buffer-usage`` conditional on Clang 16+ via ``check_c_compiler_flag``.
  * Removed hardcoded ``-g3 -O0`` (``CMAKE_BUILD_TYPE`` controls optimization).
  * Applied same strict warning set to test targets with appropriate suppressions.
  * Fixed ``-gdwarf-4`` for Valgrind compatibility with GCC 11+.
  * Ensured ``-DCMAKE_C_COMPILER=clang`` is explicitly set for all Clang builds.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : clang-tidy clean:

  * Fixed all 538 clang-tidy warnings (509 ``cert-err33-c``, 29 ``bugprone-*``).
  * Added ``(void)`` casts to ``fflush``/``fprintf``/``snprintf`` in log macros.
  * Fixed ``bugprone-macro-parentheses`` in ``ARRAY_SIZE``/``VLA_SIZE``.
  * Suppressed intentional ``bugprone-signed-char-misuse`` for EDHOC connection ID conversions.
  * Changed clang-tidy to use Clang compile database (avoids GCC-only flag errors).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Zephyr benchmark application (``sample/benchmark/``):

  * Full EDHOC handshake benchmark for Zephyr ``native_sim`` (cipher suite 2, P-256/ES256).
  * Per-phase handshake timing using POSIX ``clock_gettime`` with JSON output.
  * Library flash footprint analysis via ``nm`` on the final linked binary (~20 KiB).
  * PSA crypto and mbedTLS PK module enabled via Kconfig and ``user-mbedtls.h`` overlay.
  * NSI two-stage linking solved by providing mbedTLS archives to ``RUNNER_LINK_LIBRARIES``.
  * Removed old x86-only benchmark binaries (``tests/benchmark/``) and ``./scripts/ci.sh benchmark``.
  * Removed old minimal Zephyr sample (``sample/src/main.c``); only the benchmark app remains.
  * CI uploads ``flash_report.txt`` and ``benchmark_timing.json`` as artifacts.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Test refactoring and audit:

  * Extracted shared test helpers (``test_cipher_suites``, ``test_credentials``, ``test_ead``).
  * Removed duplicated cipher suite definitions and callback stubs across unit, integration, and fuzz tests.
  * Added missing negative test scenarios for ``edhoc_export_oscore_session`` and ``edhoc_message_1_compose/process``.
  * Consolidated fuzz targets from ``fuzz/`` into ``tests/fuzz/``.
  * Fixed GCC extension usage (non-constant struct initializers) for Clang compatibility.
  * Fixed out-of-bounds write in ``test_internals.c`` (``alg_bstr`` array).
  * Fixed ``-Wformat-truncation`` in log backend timestamp formatting.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation updates:

  * Updated test documentation with local reproducibility table and benchmark section.
  * Added compiler selection table explaining GCC vs Clang usage per task.
  * Updated memory footprint and performance benchmark tables in README to use Zephyr ``native_sim`` data.

Version 1.4.2
-------------

:Date: January 30, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation improvements and updates.

Version 1.4.1
-------------

:Date: January 30, 2026

* `@tgujda <https://github.com/tgujda>`__ : Added log module declaration for EDHOC helpers.

Version 1.4.0
-------------

:Date: January 30, 2026

* `@tgujda <https://github.com/tgujda>`__ : Added cmake install target for library installation.
* `@magdalena-szumny <https://github.com/magdalenaszumny>`__ : Added extra logs for EDHOC helpers module

Version 1.3.0
-------------

:Date: January 27, 2026

* `@magdalena-szumny <https://github.com/magdalenaszumny>`__ : 

  * Added EDHOC helpers module with connection ID and buffer utilities.
  * Renamed cipher suite files and functions to edhoc_cipher_suite_X for consistency.
  * Refactored cipher suite implementations to expose struct edhoc_crypto and struct edhoc_keys.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed Zephyr logging backend.

Version 1.2.0
-------------

:Date: January 27, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added new logging module:

  * Logging module has the same signatures to the Zephyr logging module.
  * Added logging backends for Linux and Zephyr platforms.
  * Added EDHOC_LOG_ERR for the entire library.
  * Replaced context.logger with new logging hexdump functionlike-macros.

Version 1.1.1
-------------

:Date: January 8, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed Zephyr build github workflow.

Version 1.1.0
-------------

:Date: January 7, 2026

* `@magdalena-szumny <https://github.com/magdalenaszumny>`__ : Added Zephyr build system support.
* `@magdalena-szumny <https://github.com/magdalenaszumny>`__ : Added Zephyr sample application for build verification (native_sim).
* `@magdalena-szumny <https://github.com/magdalenaszumny>`__ : Added west manifest (west.yml) for Zephyr workspace initialization.

Version 1.0.0
-------------

:Date: April 14, 2025

* `@marek-serafin <https://github.com/stoprocent>`__ : Fixed some minor issues with sizes.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added module tests for public API.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added peer cipher suites caching for message 1 process.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored cipher suites negotiation module tests.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Updated readme.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored Kconfig:

  * Moved hardcoded values from cmake to build script.
  * Renamed two variables according to style.
  * Zephyr environment variable in cmake.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Cleaned up cppcheck warnings in module tests.

Version 0.6.0
-------------

:Date: October 31, 2024

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added C unit test framework - Unity.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Migrated all module tests to Unity framework.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added documentation for:

  * Library configuration.
  * Module tests scenarios.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added missing doxygen for API.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Update zcbor from v0.7.0 to v0.8.1.

Version 0.5.0
-------------

:Date: August 5, 2024

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Changed build system from Make to CMake.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added building library code with clang compiler.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added new module test for scenario:

  * X.509 chain, cipher suite 2, static DH keys, single EAD token.

* `@marek-serafin <https://github.com/stoprocent>`__ : Fixed setting correct cases for static dh methods.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored message_2 and message_3 for common code:

  * CBOR utilities.
  * MAC 2/3 context generation.
  * MAC 2/3 computation.
  * Signature_or_MAC 2/3 computation and verification.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed setting correct cases for methods for message_3.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added any cborised authentication credentials option.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed end entity certificate according to COSE X.509 chain.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed wrong MAC length for static DH in test suite.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored EDHOC API and EDHOC interfaces.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added library zephyrization.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored function edhoc_set_methods for more flexibility.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added support for MSVC _alloca (lack of VLA).

Version 0.4.0
-------------

:Date: July 5, 2024

* `@marek-serafin <https://github.com/stoprocent>`__ : Fixed typo in setting peer_cid while processing message 1.
* `@marek-serafin <https://github.com/stoprocent>`__ : Fixed zcbor. Added a method to avoid generation of duplicated types.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added EDHOC error message compose & process with unit tests.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added EDHOC PRK exporter with unit test.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fixed CDDL models for COSE X.509 chain and COSE X.509 hash.
  
  * added unit test with two certificates for X.509 chain for cipher suite 0.
  * added unit test with one certificate for X.509 chain for cipher suite 2 with multiple EAD tokens.
  * added unit test for X.509 hash for cipher suite 2 with single EAD token.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Changed licence from GPL-2.0 to MIT.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Forbidden passing empty byte string for connection identifier.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added EDHOC error getters for: error code and cipher suites.

  * added test scenarios according to RFC 9528: 6.3.2. Examples. Covered figures 8 and 9.

Version 0.3.0
-------------

:Date: May 20, 2024

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Full support of RFC 9528 (EDHOC).

  * add missing static diffie hellman keys authentication method.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Implementation is verified with RFC 9529 (EDHOC traces) for chapter 3.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Create documentation for sphinx including:

  * move README to sphinx.
  * move ChangeLog to sphinx.
  * create API documentation and fix header files.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Add documentation deployment step for github actions.

Version 0.2.0
-------------

:Date: April 28, 2024

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Update implementation for RFC 9528 (EDHOC) including:

  * external authorization data aligned with RFC.
  * add message 4 compose & process.
  * keyUpdate method.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Separate interface for EAD.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Implementation is verified with RFC 9529 (EDHOC traces) for chapter 2.

  * extended unit tests with EAD single/multiple tokens.
  * used RFC 9529 certificates to verify authentication identified by 'x5chain'.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Example implementation of cipher suite 2.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : EDHOC context structure with private members.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix connection identifiers encoding option.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix authentication credentials encoding option.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix CBOR memory requirements for integer, byte string and text string.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Add build, run unit tests and verification by cppcheck and valgrind for github actions.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Update README.

Version 0.1.0
-------------

:Date: April 01, 2024

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : EDHOC implementation for version 16:

  * limited support for authentication methods only via signatures.
  * support EAD encoded as byte string.
  * support authentication identified by: 'kid', 'x5chain', 'x5t'.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CoAP friendly EDHOC API.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Separate interfaces for:

  * cryptographics keys.
  * cryptographics operations.
  * authentication credentials.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Authentication credentials fetch callback accept only private key identifier.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Example implementation of cipher suite 0 with PSA.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Unit test with test vectors for authentication with signatures, X.509 identified by 'kid', 'x5chain' and 'x5t'.
