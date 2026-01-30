Module tests scenarios
======================

:file:`module_test_api.c`
      | Tests for EDHOC public API functions.

:file:`module_test_rfc9529_chapter_2.c`
      | Test vector was taken from `RFC9529`_ chapter 2.
      | It contains authentication with signatures, X.509 identified by 'x5t'.

      Following scenarios were prepared:

      * message <1, 2, 3, 4> compose and process.

      * message <2, 3> compose with already cborised authentication credentials.

      * full handshake between initiator and responder based on test vector. Additionally it contains:

        * derivation of OSCORE sessions.

        * key update for generation new shared secret and new OSCORE sessions.

      * full handshake with real crypto where we verify if OSCORE session are equals.

      * full handshake with real crypto with external authorization data (EAD):

        * single EAD token.

        * multiple EAD tokens.

:file:`module_test_rfc9529_chapter_3.c`
      | Test vector was taken from `RFC9529`_ chapter 3.
      | It contains authentication with static DH, CCS identified by 'kid'.

      Following scenarios were prepared:

      * message <1, 2, 3, 4> compose and process.

      * message <2, 3> compose with already cborised authentication credentials.

      * full handshake between initiator and responder based on test vector. Additionally it contains:

        * derivation of OSCORE sessions.

        * key update for generation new shared secret and new OSCORE sessions.

:file:`module_test_rfc9528_suites_negotiation.c`
      | Examples for scenarios was taken from `RFC9528`_, chapter 6.3.2.
      | We can verify EDHOC error codes and cached cipher suites in case of cipher suites mismatch.
      
      Following scenarios were prepared:

      * cipher suite negotiation where initiator sent only one suite. (Figure 8)

      * cipher suite negotiation where initiator sent a list of suites. (Figure 9)

:file:`module_test_error_message.c`
      | EDHOC error message was taken from `RFC9528`_, chapter 6.
      | We can verify error message compose and process.

      Following scenarios were prepared:

      * error message compose and process for: 
      
        * success.

        * unspecified error.

        * wrong selected cipher suite.

        * unknown credential referenced.

:file:`module_test_x5chain_sign_keys_suite_0.c`
      | Full handshake with real crypto where we verify if OSCORE session are equals.
      | It contains authentication with signatures, X.509 identified by 'x5chain', cipher suite 0.
      | We verify one and two certificates in chain.

:file:`module_test_x5chain_sign_keys_suite_2.c`
      | Full handshake with real crypto where we verify if OSCORE session are equals.
      | It contains authentication with signatures, X.509 identified by 'x5chain', cipher suite 2.
      | We verify one certificates in chain with/without multiple EAD tokens.

:file:`module_test_x5chain_static_dh_keys_suite_2.c`
      | Full handshake with real crypto where we verify if OSCORE session are equals.
      | It contains authentication with static DH, X.509 identified by 'x5chain', cipher suite 2.
      | We verify one certificates in chain with single EAD token.

:file:`module_test_x5t_sign_keys_suite_2.c`
      | Full handshake with real crypto where we verify if OSCORE session are equals.
      | It contains authentication with signatures, X.509 identified by 'x5t', cipher suite 2.
      | We verify certificate hashes with single EAD token.

:file:`module_test_cipher_suite_0.c`
      | Verification of EDHOC cipher suite 0 implementation for ECDSA, ECDH, HKDF, AEAD and HASH.

:file:`module_test_cipher_suite_2.c`
      | Verification of EDHOC cipher suite 2 implementation for ECDSA, ECDH, HKDF, AEAD and HASH.

:file:`module_test_edhoc_helpers.c`
      | Tests for helper functions that facilitate interactions between EDHOC and CoAP transport.

.. _`RFC9528`: https://datatracker.ietf.org/doc/html/rfc9528
.. _`RFC9529`: https://datatracker.ietf.org/doc/html/rfc9529
