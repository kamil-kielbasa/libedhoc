/**
 * \file    edhoc_cipher_suite_pqc_1.h
 * \author  Kamil Kielbasa
 * \brief   Post-quantum cipher suite 1 (TBD1, draft-ietf-lake-pqsuites-00)
 *          contains:
 *            - AEAD algorithm                      = AES-CCM-16-128-128
 *            - hash algorithm (key derivation)     = SHAKE256
 *            - MAC length in bytes (Static DH)     = 16
 *            - key exchange algorithm (KEM)        = ML-KEM-512
 *            - signature algorithm                 = ML-DSA-44
 *
 * \details ML-KEM-512 and ML-DSA-44 use liboqs; SHAKE256 and the KMAC256 KDF
 *          use liboqs and XKCP; AES-CCM uses PSA. The oversized ML-KEM
 *          decapsulation key and ML-DSA signing key are held in a software
 *          keystore local to this suite because PSA cannot store key material
 *          this large; every other key stays in PSA.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_PQC_1_H
#define EDHOC_CIPHER_SUITE_PQC_1_H

/* Include files ----------------------------------------------------------- */

#include <edhoc/edhoc_crypto.h>
#include <edhoc/edhoc_cipher_suite.h>

#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-cipher-suite-pqc-1-api Post-quantum cipher suite 1 API
 *
 * \details Cipher suite 1 (TBD1) from draft-ietf-lake-pqsuites-00: ML-KEM-512 /
 *          ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256. The ephemeral key
 *          exchange is a KEM, so \c G_X carries the ML-KEM encapsulation key
 *          and \c G_Y carries the ML-KEM ciphertext. ML-KEM is not a NIKE, so
 *          only the signature authentication method applies.
 *
 * @{
 */

/**
 * \brief Get the crypto operations for post-quantum cipher suite 1.
 *
 * \return Pointer to the post-quantum cipher suite 1 crypto vtable.
 */
const struct edhoc_crypto *edhoc_cipher_suite_pqc_1_get_crypto(void);

/**
 * \brief Get the cipher suite descriptor for post-quantum cipher suite 1.
 *
 * \return Pointer to the post-quantum cipher suite 1 descriptor.
 */
const struct edhoc_cipher_suite *edhoc_cipher_suite_pqc_1_get_suite(void);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_PQC_1_H */
