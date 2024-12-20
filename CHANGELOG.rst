Next version
------------

:Date: January X, 2025

* `@marek-serafin <https://github.com/stoprocent>`__ : Fixed some minor issues with sizes.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added module tests for public API.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Added peer cipher suites caching for message 1 process.
* `@kamil-kielbasa <https://github.com/kamil-kielbasa>`__ : Refactored cipher suites negotiation module tests.

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
