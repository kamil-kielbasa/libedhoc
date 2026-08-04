/**
 * \file    edhoc_kdf_kmac256.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC KDF (EDHOC_Extract / EDHOC_Expand) for the SHAKE256 suite,
 *          expressed as KMAC256 per RFC 9528 Section 4.1.
 *
 *          This is a thin, backend-agnostic interface. The implementation
 *          shipped here is edhoc_kdf_kmac256_xkcp.c, which delegates to the
 *          XKCP SP800-185 KMAC256(). Because the interface is backend-agnostic,
 *          an equivalent self-contained KMAC256 could be substituted without
 *          touching the cipher suite or the tests.
 *
 *          The backend is conformant to NIST SP 800-185 (verified against
 *          KMAC256 known-answer tests and the EDHOC_Extract/EDHOC_Expand
 *          vectors in test_cipher_suite_pqc_1.c).
 *
 *          RFC 9528 Section 4.1 (SHAKE256 / KMAC256 suite):
 *            EDHOC_Extract(salt, IKM)   = KMAC256(salt, IKM, 8*32 .. , "")
 *            EDHOC_Expand(PRK, info, L) = KMAC256(PRK,  info, 8*L,     "")
 *          i.e. KMAC256 keyed by the first argument, with an EMPTY
 *          customization string S = "", and an output length in bits equal to
 *          8 * (requested output length in bytes).
 *
 * \copyright Copyright (c) 2026
 *
 */

#ifndef EDHOC_KDF_KMAC256_H
#define EDHOC_KDF_KMAC256_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Function prototypes ----------------------------------------------------- */

/**
 * \brief Compute KMAC256 as used by the EDHOC SHAKE256 cipher suite.
 *
 *        Equivalent to NIST SP 800-185 KMAC256(key, input, 8*output_length,
 *        ""), i.e. an EMPTY customization string and a fixed output length of
 *        \p output_length bytes. This single primitive implements BOTH
 *        EDHOC_Extract (key = salt, input = IKM, output_length = hash length)
 *        and EDHOC_Expand (key = PRK, input = info, output_length = requested
 *        length).
 *
 *        All lengths are in BYTES. Inputs are arbitrary-length byte strings;
 *        there are no fixed internal size limits (the back-ends stream the
 *        input through the Keccak sponge).
 *
 * \param[in]  key            KMAC key (EDHOC salt or PRK). Must not be NULL.
 * \param      key_length     Length of \p key in bytes (may be 0..n).
 * \param[in]  input          KMAC message (EDHOC IKM or info). May be NULL iff
 *                            \p input_length is 0.
 * \param      input_length   Length of \p input in bytes.
 * \param[out] output         Output buffer; receives \p output_length bytes.
 * \param      output_length  Requested output length in bytes (> 0).
 *
 * \retval #EDHOC_SUCCESS on success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT on NULL/zero-length misuse.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE if the underlying KMAC256 fails.
 */
int edhoc_kdf_kmac256(const uint8_t *key, size_t key_length,
		      const uint8_t *input, size_t input_length,
		      uint8_t *output, size_t output_length);

#endif /* EDHOC_KDF_KMAC256_H */
