Version 2.0.0
-------------

:Date: Unreleased

**Breaking release.** Changes accumulate here as they land.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Public API layout
  (breaking):

  * All public headers now live under ``include/edhoc/``. Include the library
    through the umbrella ``<edhoc/edhoc.h>``, or pick individual headers such as
    ``<edhoc/edhoc_crypto.h>``. Replace any ``#include <edhoc.h>`` (or
    ``"edhoc_*.h"``) with the ``<edhoc/...>`` form.
  * New header ``<edhoc/edhoc_cipher_suite.h>`` holds ``struct
    edhoc_cipher_suite``, the new ``enum edhoc_cipher_suite_id`` and the
    recommended getters ``edhoc_cipher_suite_get_params(id)`` /
    ``edhoc_cipher_suite_get_crypto(id)`` (keyed by suite id; the per-suite
    ``edhoc_cipher_suite_N_get_*()`` getters remain available).
  * The connection-id and message-framing helpers move to
    ``<edhoc/edhoc_coap.h>`` and gain an ``edhoc_coap_`` prefix — for example
    ``edhoc_prepend_flow()`` becomes ``edhoc_coap_prepend_flow()`` and
    ``edhoc_extract_connection_id()`` becomes
    ``edhoc_coap_extract_connection_id()``. They are now part of the core
    library, so there is no separate helper source to compile.
  * Each reference cipher suite has a Kconfig gate
    ``CONFIG_LIBEDHOC_CIPHER_SUITE_{0,2,24,PQC_1}_ENABLE``. Disabling a suite
    drops it from the build and makes ``edhoc_cipher_suite_get_*()`` return
    ``NULL`` for that suite.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Opaque context and
  mandatory platform binding (breaking):

  * ``struct edhoc_context`` is now opaque — its layout is no longer part of the
    public API and the ``EDHOC_PRIVATE()`` accessor macro is removed. Size the
    storage with ``edhoc_context_size()`` (stack VLA or heap) instead of
    declaring a ``struct edhoc_context`` by value, then call
    ``edhoc_context_init()``.
  * New mandatory platform binding: bind a ``struct edhoc_platform`` — a
    non-elidable ``zeroize`` callback — with ``edhoc_bind_platform()`` before
    running the handshake. The message compose/process API returns
    ``EDHOC_ERROR_BAD_STATE`` until it is bound. End-of-life erasure of secrets
    and key identifiers now routes through this hook.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : New crypto vtable and
  mbedTLS update to v4.1.0 with cipher suite 2 alignments.

Version 1.15.1
--------------

:Date: July 9, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CI: the Valgrind
  job no longer builds the experimental PQC cipher suite. liboqs dispatches
  hand-written AVX2/AVX-512 ML-KEM code at runtime and Valgrind cannot decode
  some of those opcodes, which aborted the run with SIGILL on AVX-512-capable
  runners. No library code changed.

Version 1.15.0
--------------

:Date: July 8, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Cipher suites:

  * Added **cipher suite 4** (ChaCha20/Poly1305, SHA-256, X25519, EdDSA) as a ready-to-use helper.

Version 1.14.1
--------------

:Date: July 1, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Experimental PQC
  cipher suite 1:

  * Fixed ``EDHOC_Extract`` / ``EDHOC_Expand``: KMAC256 (RFC 9528 Section 4.1)
    is now computed by XKCP and conforms to NIST SP 800-185, so the suite
    derives correct keys. Verified against the published NIST KMAC256
    known-answer vector.
  * Enabling ``LIBEDHOC_ENABLE_EXPERIMENTAL_PQC`` now also builds XKCP and
    requires ``xsltproc`` on the host.

Version 1.14.0
--------------

:Date: June 17, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : PQC:

  * Added experimental **PQC cipher suite 1** helper (draft TBD1) for
    `draft-spm-lake-pqsuites-02
    <https://datatracker.ietf.org/doc/html/draft-spm-lake-pqsuites-02>`_:
    ML-KEM-512 key exchange, ML-DSA-44 signatures, AES-CCM-16-128-128 AEAD,
    SHAKE256 hash, and KMAC256 extract/expand (RFC 9528 Section 4.1).
  * Introduced ``struct edhoc_crypto_pqc`` and ``struct edhoc_cipher_suite_pqc``
    in :file:`helpers/include/edhoc_exp_pqc_cipher_suite_1.h` (KEM-shaped crypto
    vtable; ``encapsulate`` / ``decapsulate`` replace ``key_agreement``).
  * Key import uses ``PSA_KEY_TYPE_RAW_DATA`` for ML-KEM / ML-DSA material;
    ephemeral ML-KEM keys use static slots simulating PSA key identifiers.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Build:

  * Added ``externals/liboqs`` git submodule pinned to tag **0.15.0** and west
    project ``modules/lib/liboqs``.
  * New CMake option ``LIBEDHOC_ENABLE_EXPERIMENTAL_PQC`` (default **OFF**)
    builds liboqs with ``KEM_ml_kem_512`` and ``SIG_ml_dsa_44`` only.
  * Renamed ``LIBEDHOC_ENABLE_MODULE_TESTS`` to ``LIBEDHOC_ENABLE_TESTS``.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Tests:

  * Added Unity group ``cipher_suite_exp_pqc_1`` (ML-KEM, ML-DSA, hash, KMAC,
    AES-CCM round-trips on Linux).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Coverage / docs:

  * New guide ``guide/pqc`` (experimental PQC cipher suite 1), README
    experimental cipher-suite section, and helpers.rst section for experimental
    PQC cipher suite 1.

Version 1.13.0
--------------

:Date: June 17, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : API:

  * Removed callback ``typedef``\ s from the public headers and inlined the
    function pointers directly into their binding structs
    (``struct edhoc_credentials``, ``struct edhoc_keys``, ``struct edhoc_crypto``,
    ``struct edhoc_ead``), Zephyr-style. The associated Doxygen was moved onto
    each struct member. No function signatures, struct names, struct layouts or
    behavior change; ABI is unchanged. Existing code that supplies callbacks via
    designated initializers requires no changes. Only code that referenced the
    removed ``edhoc_*_t`` type names directly is affected.

Version 1.12.7
--------------

:Date: June 16, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CBOR:

  * Removed duplicate ``cbor_bstr_overhead`` helpers from message 4 and the
    exporter; all byte-string buffer sizing now uses ``edhoc_cbor_bstr_oh``.
  * ``edhoc_cbor_bstr_oh`` returns the canonical 1-byte header for lengths
    ≤ 23 (removed legacy zcbor padding).
  * Dropped redundant literal ``+1`` header counts in ``comp_cid_len``,
    ``compute_plaintext_4_len``, exporter empty-bstr sizing, and message 2
    signature encode buffers.

Version 1.12.6
--------------

:Date: June 16, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Build:

  * Centralized warning flags in :file:`cmake/warnings.cmake`
    (``libedhoc_target_warnings(STRICT|TEST)``) for library, tests, and fuzz.
  * Unified zcbor compile definitions via ``LIBEDHOC_ZCBOR_COMPILE_DEFINITIONS``;
    removed unused ``CONFIG_ZCBOR``; ``ZCBOR_CANONICAL`` consistently ``PRIVATE``.
  * Fixed ``CMakePresets.json`` schema version (6 → 3) to match ``cmake_minimum_required`` 3.21.
  * Install of generated ``edhoc_config.h`` uses ``LIBEDHOC_GENERATED_DIR`` instead of a hardcoded path.

Version 1.12.5
--------------

:Date: June 16, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Tests:

  * Assert specific ``EDHOC_ERROR_*`` return codes instead of generic
    success/failure checks across integration and unit tests.
  * Removed ``goto``-based cleanup from integration test helpers; use
    structured early returns instead.
  * Strengthened integration tests: ``psa_crypto_init()`` checks in setup,
    ``edhoc_context_deinit()`` asserts in teardown, and direct
    ``edhoc_cipher_suite_N_get_suite()`` / ``_get_keys()`` getter calls
    where a cached pointer added no value.
  * Added ``get_cipher_suite_descriptors`` test in
    :file:`tests/unit/api/test_api.c` for cipher suite 0, 2, and 24 getters.
  * Documented test quality standards in :file:`doc/project/testing.rst`.
  * Added :file:`coverage_sweep.h` and :file:`test_coverage_sweep_validate.c`:
    per-``fail_pt`` expected outcomes for mock sweeps via ``coverage_assert_sweep_result()``.
  * Extended mock full-handshake coverage tests to message 4; hardened
    :file:`coverage_common.c` setup.

Version 1.12.4
--------------

:Date: June 16, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Tests:

  * Split :file:`test_coverage.c` (142 cases) into eight topic files under
    :file:`tests/unit/coverage/` with shared :file:`coverage_common.c`.
  * Split :file:`test_internals.c` (232 cases) into nine topic files under
    :file:`tests/unit/internals/` with shared :file:`internals_common.c`.
  * Removed ``@scenario`` / ``@env`` / ``@action`` / ``@expected`` comment
    blocks; test names are self-describing.
  * Renamed ``TEST_GROUP`` identifiers to match file topics (e.g.
    ``coverage_msg1``, ``internals_mac``).
  * Added ``edhoc_macros.h`` to :file:`test_common.h` for ``ARRAY_SIZE``.
  * Renamed compile definition ``EDHOC_MODULE_TESTS`` to
    ``LIBEDHOC_MODULE_TESTS``.

Version 1.12.3
--------------

:Date: June 15, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Tests:

  * Replaced ``LIBEDHOC_TEST_HOOKS`` / ``edhoc_test_*`` wrappers with a
    ``STATIC`` linkage macro in :file:`include/edhoc_macros.h`, enabled by
    ``EDHOC_MODULE_TESTS`` when module tests are built.
  * Reorganised unit tests into topic subdirectories under
    :file:`tests/unit/` (``api/``, ``cipher_suites/``, ``coverage/``,
    ``internals/``, etc.).

Version 1.12.2
--------------

:Date: June 15, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Build system:

  * The CMake setup was reorganised around namespaced targets
    (``libedhoc::edhoc``, ``libedhoc::api``, ``libedhoc::helpers``,
    ``libedhoc::backend_*``). Plain target names are kept for backward
    compatibility, and ``EXPORT_NAME`` makes ``find_package()`` and
    ``add_subdirectory()`` consumers use identical names.
  * Backends are now linked ``PRIVATE`` on the core, so their ~40 headers no
    longer leak onto a consumer's include path. Consumers that compile the
    helper sources themselves link ``libedhoc::helpers`` (which carries the
    helper, CBOR and log include paths).
  * A single source-of-truth list (:file:`cmake/sources.cmake`) feeds both the
    standalone and the Zephyr builds, and :file:`zephyr/CMakeLists.txt` is now
    the only Zephyr-aware file — the rest of the tree has no
    ``if(TARGET zephyr_interface)`` branches.
  * A generated :file:`edhoc_config.h` (from :file:`cmake/edhoc_config.h.in`)
    guarantees every translation unit — and every installed consumer — sees
    the same build-time configuration, removing a silent cross-TU mismatch of
    ``CONFIG_LIBEDHOC_MEM_BACKEND``. On Zephyr the values still come from
    Kconfig (the include is guarded by ``__ZEPHYR__``).
  * Packaging was hardened: ``find_dependency(zcbor)`` in the package config, a
    generated package-version file, namespaced exported targets, and the
    convenience helper *sources* installed under :file:`share/` instead of the
    CMake-package directory.
  * Added :file:`CMakePresets.json` (``gcc``/``clang``/``coverage``/
    ``sanitizers``/``fuzz``). The minimum CMake version is now 3.21.
  * This is a build-system change only: the public API, headers and runtime
    behaviour are unchanged.

Version 1.12.1
--------------

:Date: June 12, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Logging backend:

  * The logging facility moved into a single, pluggable backend header,
    :file:`backends/log/include/edhoc_backend_log.h`. The previous
    :file:`include/edhoc_log.h` and the entire :file:`port/log` directory
    (with its separate Linux and Zephyr backend files) have been removed.
  * The Linux/Zephyr split is now resolved entirely by the preprocessor
    (``__ZEPHYR__``) inside that one header, instead of by selecting a
    different include directory per platform from CMake.
  * The compile-time level gating that previously lived in
    :file:`include/edhoc_log.h` was folded into the backend header, and the
    one-time Zephyr ``LOG_MODULE_REGISTER`` is now hosted directly in
    :file:`library/edhoc.c`.
  * This is purely an internal reorganisation: the ``EDHOC_LOG_*`` macros,
    the log levels and ``CONFIG_LIBEDHOC_LOG_LEVEL`` behave exactly as before.

Version 1.12.0
--------------

:Date: June 12, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Memory backend:

  * The library can now obtain its internal working buffers from one of three
    interchangeable memory backends, chosen at build time. The default keeps
    the previous behaviour, so existing integrations are unaffected:

    * **Stack** (default) — buffers live on the call stack, exactly as before.
    * **Heap** — buffers come from the system heap (``calloc`` on hosted
      builds, ``k_calloc`` on Zephyr), removing the deep per-handshake stack
      usage on constrained targets.
    * **Custom** — the application provides its own ``edhoc_mem_alloc`` /
      ``edhoc_mem_free`` at link time, e.g. to serve buffers from a dedicated
      pool.

    The backend is chosen by the integer ``CONFIG_LIBEDHOC_MEM_BACKEND``: on
    Zephyr it is derived from the ``LIBEDHOC_MEM_BACKEND_CHOICE`` Kconfig choice,
    and on every other build it is passed directly
    (``-DCONFIG_LIBEDHOC_MEM_BACKEND=N``, where N is 0 stack, 1 heap or 2 custom;
    default 0).

  * Out-of-memory conditions are now reported to the caller. The new
    ``EDHOC_ERROR_NOT_ENOUGH_MEMORY`` (-106) error code is returned by the
    affected message and exporter APIs when a non-stack backend cannot satisfy
    an allocation, and the failing call leaves no buffers leaked behind.
  * Working buffers handed to the library are guaranteed to be zero-initialised
    on every backend.
  * The behaviour is verified for all three backends, including a tracking,
    fault-injecting custom allocator that exercises every out-of-memory path,
    and the heap backend additionally under ASan/LSan.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix:

  * Message 1 processing now rejects an empty peer cipher suite list
    (``SUITES_I``). The responder previously read the list's last entry at
    ``count - 1``; for an empty list that index underflowed to ``SIZE_MAX``
    and caused an out-of-bounds read. An empty list is now reported as a
    wrong selected cipher suite error.

Version 1.11.2
--------------

:Date: June 11, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Docs:

  * Removed the stale hardcoded "Release" admonition from ``doc/index.rst``; the project version is maintained in ``doc/conf.py``.

Version 1.11.1
--------------

:Date: June 11, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CI:

  * Added a reusable ``.github/actions/retry`` composite action and wrapped the submodule checkout. Transient GitHub network failures are retried instead of failing the job.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix:

  * Replaced the dynamic shields.io release badge in ``README.md`` with a GitHub Pages-hosted endpoint badge, so it no longer renders "Unable to select next GitHub token from pool" when the shields.io GitHub token pool is exhausted.

Version 1.11.0
--------------

:Date: June 10, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Helpers / cipher suites:

  * Added the cipher suite 24 reference helper: A256GCM, SHA-384, P-384 (secp384r1) and ES384.
  * Added ``tests/unit/test_cipher_suite_24.c`` covering the full crypto surface.
  * Documented cipher suite 24.
  * Moved the suite length macros (``EDHOC_CIPHER_SUITE_<n>_*``, suites 0/2/24) out of the public headers into each ``edhoc_cipher_suite_<n>.c``, where they seed the descriptor.
  * Renamed ``test_crypto_suite{0,2}.c`` to ``test_cipher_suite_{0,2}.c`` (groups ``cipher_suite_{0,2}``) and sized their buffers from the ``_get_suite()`` descriptors.
  * Extended ``tests/unit/test_cipher_suite_{0,2}.c`` with signature/AEAD tamper-detection and an additional HKDF-SHA-256 KAT.
  * Removed the per-test descriptive comments across ``tests/unit/test_cipher_suite_{0,2,24}.c`` in favour of self-descriptive test names.
  * Hardened ``tests/unit/test_cipher_suite_{0,2,24}.c``.

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Tests / integration:

  * Added ``tests/integration/test_handshake_x5chain_sig_suite24.c`` — a full EDHOC handshake over an X.509 certificate chain using cipher suite 24 (P-384 / ES384), with the P-384 test vector ``tests/include/test_vector_x5chain_sign_keys_suite_24.h``.
  * Raised ``CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY`` and ``CONFIG_LIBEDHOC_MAX_LEN_OF_MAC`` to 48 in ``scripts/ci.sh`` so the shared test build accommodates P-384 keys and SHA-384 transcript hashes.
  * Relaxed the X25519 ``make_key_pair`` buffer-size check in ``edhoc_cipher_suite_0.c`` to accept context buffers larger than the key (only undersized buffers are rejected).
  * Updated the ``coverage`` mock crypto in ``tests/unit/test_coverage.c`` to report fixed cipher suite 2 key/hash lengths (32) regardless of the buffer size.
  * Fixed the message 2 ECDH-secret known-answer checks in ``tests/integration/test_rfc9529_chapter{2,3}.c`` to compare ``dh_secret_len`` bytes instead of the whole buffer (``sizeof``).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Fix:

  * Helpers: corrected the cipher suite 2 descriptor MAC length (Static DH) from 32 to 8 bytes to match RFC 9528 (``edhoc_cipher_suite_2_get_suite``).

Version 1.10.3
--------------

:Date: June 5, 2026

* `@orbisai0security <https://github.com/orbisai0security>`__ : Security:

  * Helpers: fixed buffer overread in P-256 public-key decompression — an
    oversized compressed peer key could write past the decompressed-key buffer;
    keys longer than the curve field size are now rejected before copying (V-001).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Coverage / docs:

  * Helpers: documented the P-256 decompression bounds check as defensive and unreachable through the public API.
  * Tests: clarified that ``key_agreement_peer_key_oversized_33`` exercises the ``key_agreement`` length guard rather than the ``mbedtls_ecp_decompress`` bounds check.

Version 1.10.2
--------------

:Date: June 2, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : CI / contributing:

  * Added the ``CI / Format`` GitHub Actions workflow that runs ``clang-format --dry-run --Werror`` over every tracked ``*.c`` / ``*.h`` file (excluding the zcbor-generated ``backends/cbor/`` tree).
  * Reformatted to satisfy the new check.
  * Documented in ``CONTRIBUTING.md`` that every PR must update ``CHANGELOG.rst`` with a matching entry.

Version 1.10.1
--------------

:Date: June 2, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Library:

  * Added ``edhoc_cipher_suite_0_get_suite()`` and ``edhoc_cipher_suite_2_get_suite()`` returning a pointer to a pre-initialized canonical ``struct edhoc_cipher_suite`` (mirrors the existing ``_get_keys`` / ``_get_crypto`` getters).
  * Migrated all callers to the new getters and removed the now-redundant ``tests/common/{include,src}/test_cipher_suites.{h,c}`` (and their CMake entries).

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Doxygen cleanup:

  * Removed stale ``\version`` and ``\date`` tags from all library, helper, port, sample and test file headers.

Version 1.10.0
--------------

:Date: June 2, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Documentation overhaul:

  * Restructured Sphinx docs into ``getting_started/``, ``guide/``, ``api/``, ``reference/`` and ``project/`` sections; switched to the Furo theme.
  * Split the monolithic API page into per-topic pages (context, messages, credentials, crypto, exporters, EAD, helpers, internals).
  * Added a glossary, an error-code reference, a values reference and a links page.
  * Refreshed ``README.md`` (two-row badge layout) and rewrote ``CONTRIBUTING.md`` with the unified ``scripts/ci.sh`` workflow and shallow ``west update``.

Version 1.9.0
-------------

:Date: June 1, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Library / helpers (log footprint):

  * Shortened ``EDHOC_LOG_*`` message literals across ``library/*.c`` and ``helpers/src/*.c`` to reduce flash footprint when logging is enabled.

Version 1.8.0
-------------

:Date: June 1, 2026

* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Library (``edhoc_macros.h``):

  * Added ``EDHOC_ASSERT_FREE_STACK_SIZE``: on Zephyr expands to a runtime free-stack check via ``k_thread_stack_space_get`` + ``__ASSERT``, otherwise no-op.
  * ``VLA_ALLOC`` now calls ``EDHOC_ASSERT_FREE_STACK_SIZE`` on Linux/Zephyr.
  * Reorganized Doxygen for platform-dependent macros using the ``__DOXYGEN__`` stub pattern.

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
