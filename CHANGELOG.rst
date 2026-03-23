Version 1.7.1
-------------

:Date: March 23, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Testing:

  * Cipher suite 2 (``tests/unit/test_crypto_suite2.c``): invalid key material for import; HKDF extract/expand when ``psa_key_derivation_set_capacity`` rejects oversized output; AEAD encrypt/decrypt with zero-length plaintext (null message buffers where PSA allows for AES-CCM).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation:

  * Updated Sphinx ``conf.py`` version to v1.7.1.

Version 1.7.0
-------------

:Date: March 20, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Cipher suite 2 reference helper (``helpers/src/edhoc_cipher_suite_2.c``):

  * ES256: ``edhoc_cipher_suite_2_hash`` then ``psa_sign_hash`` / ``psa_verify_hash`` (was ``psa_sign_message`` / ``psa_verify_message``); equivalent to ``PSA_ALG_ECDSA(PSA_ALG_SHA_256)`` on the full message.
  * Hash-then-sign lowers I/O for large sign payloads (e.g. secure elements). Callback ``input`` is unchanged: full byte string from the library.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation:

  * Cipher suite 2 Doxygen and ``api.rst`` note.
  * Updated Sphinx ``conf.py`` version to v1.7.0.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Library (volatile key handles):

  * ``memset`` local ``key_id`` after ``destroy_key`` in ``edhoc_message_{1,2,3}.c`` (aligned with the rest of the library).

Version 1.6.0
-------------

:Date: March 1, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : API symbol corrections (deprecated aliases preserved):

  * Renamed ``EDHOC_SM_RECEVIED_M4`` → ``EDHOC_SM_RECEIVED_M4``.
  * Renamed ``EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2`` → ``EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2``.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : API documentation audit:

  * Standardized all ``\retval`` descriptions in ``edhoc.h`` for clarity and consistency.
  * Added missing ``\retval #EDHOC_ERROR_BUFFER_TOO_SMALL`` for ``edhoc_message_1_compose`` and ``edhoc_export_oscore_session``.
  * Corrected ``\param`` directions and descriptions in ``edhoc_crypto.h`` (e.g. ``public_key_length``, ``hash`` output direction).
  * Fixed process function ``message_N_length`` descriptions (length of message, not buffer size).
  * Fixed grammar and CBOR capitalization in ``edhoc_credentials.h`` and ``edhoc_context.h``.
  * Added comprehensive Doxygen for all macros in ``edhoc_macros.h`` (``\defgroup edhoc-macros``).
  * Added ``\author`` to ``edhoc_test_hooks.h``.
  * Fixed duplicate ``\defgroup`` in ``edhoc_helpers.h``.
  * Unified ``\return`` / ``\retval`` style across all callback typedefs and internal functions.
  * Corrected ``\ref`` → ``\see`` for external URLs in Doxygen.
  * Fixed ``#error`` message for ``CONFIG_LIBEDHOC_MAX_LEN_OF_MAC``.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Spelling corrections across all headers:

  * ``psuedorandom`` → ``pseudorandom``, ``crypographics`` → ``cryptographic``.
  * ``Diffie-Helmann`` → ``Diffie-Hellman``, ``registery`` → ``registry``.
  * ``conatins`` → ``contains``, ``definitiones`` → ``definitions``.
  * ``identifer`` → ``identifier``, ``buffor`` → ``buffer``.
  * Renamed ``psuedo_random_key`` → ``pseudo_random_key`` in cipher suite header declarations.
  * Corrected ``\file`` tag in Zephyr log backend to match actual filename.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added Doxygen for internal modules:

  * Added ``\defgroup edhoc-log`` with documentation for all log levels and log macros.
  * Added Doxygen for Linux log backend: ``edhoc_log_get_timestamp``, ``edhoc_log_hexdump_impl``, ANSI color defines.
  * Added Doxygen for Zephyr log backend macro wrappers.
  * Added ``\defgroup edhoc-test-hooks`` with ``\brief`` for all 40+ test hook functions.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation improvements:

  * Added "Lifecycle" section to ``api.rst`` with context initialization call order and code examples.
  * Added "Error handling" section to ``api.rst`` with error code retrieval guidance.
  * Fixed ``edhoc_set_conn_id()`` → ``edhoc_set_connection_id()`` in API flow diagram.
  * Fixed cipher suite 0 algorithm description: ECDSA → EdDSA in ``testing.rst``.
  * Fixed west build path for benchmark sample in ``configuration.rst``.
  * Updated Sphinx ``conf.py`` version to v1.6.0.

Version 1.5.0
-------------

:Date: February 27, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CI/CD pipeline overhaul:

  * Consolidated all CI logic into a single ``scripts/ci.sh`` entry point for local reproducibility.
  * Added code coverage measurement with gcov/lcov and Codecov integration.
  * Added ASan + UBSan sanitizer CI job (GCC).
  * Added LibFuzzer-based fuzz testing CI job (Clang).
  * Added weekly scheduled CI workflow with extended fuzzing.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Compiler flags hardening:

  * Unified GCC and Clang warning flags (~25 shared flags).
  * Added GCC-specific warnings: ``-Wformat-overflow=2``, ``-Wformat-truncation=2``, ``-Wswitch-enum``, ``-Wjump-misses-init``, ``-Wduplicated-cond``, ``-Wduplicated-branches``, ``-Wlogical-op``.
  * Added ``-fstack-protector-strong`` for non-sanitizer builds.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Resolved all 538 clang-tidy warnings across the library.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Zephyr benchmark application (``sample/benchmark/``):

  * Full EDHOC handshake benchmark for ``native_sim`` (cipher suite 2, P-256/ES256, X.509 chain).
  * Per-phase handshake timing with JSON output.
  * Library flash footprint analysis (~20 KiB).
  * NSI two-stage linking solved by providing mbedTLS archives to ``RUNNER_LINK_LIBRARIES``.
  * CI uploads ``flash_report.txt`` and ``benchmark_timing.json`` as artifacts.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Test improvements:

  * Restructured tests into 3-tier architecture: unit, integration, and fuzz.
  * Extracted shared test helpers (``test_cipher_suites``, ``test_credentials``, ``test_ead``).
  * Added negative test scenarios for ``edhoc_export_oscore_session`` and ``edhoc_message_1_compose/process``.
  * Added mock-based failure injection tests for internal error paths.
  * Consolidated fuzz targets from ``fuzz/`` into ``tests/fuzz/``.
  * Achieved 92.8% line coverage and 100% function coverage (635+ tests).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Bug fixes:

  * Fixed out-of-bounds write in ``test_internals.c`` (``alg_bstr`` array).
  * Fixed GCC extension usage (non-constant struct initializers) for Clang compatibility.
  * Fixed ``-Wformat-truncation`` in log backend timestamp formatting.
  * Fixed ``-gdwarf-4`` for Valgrind compatibility with GCC 11+.

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
