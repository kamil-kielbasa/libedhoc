/**
 * \file    edhoc_cipher_suite_2.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 2 contains:
 *            - AEAD algorithm                      = AES-CCM-16-64-128
 *            - hash algorithm                      = SHA-256
 *            - MAC length in bytes (Static DH)     = 8
 *            - key exchange algorithm (ECDH curve) = P-256
 *            - signature algorithm                 = ES256
 *
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_2_H
#define EDHOC_CIPHER_SUITE_2_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include <edhoc/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/** \defgroup edhoc-cipher-suite-2-api EDHOC cipher suite 2 API
 *
 * \details Reference implementation of EDHOC cipher suite 2
 *          (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256), built on PSA crypto
 *          (mbedTLS). The ephemeral key exchange is a NIKE-as-KEM shim over
 *          ECDH P-256 (\c generate_key_pair / \c encapsulate / \c decapsulate);
 *          static-DH authentication (methods 1/2/3) uses \c key_agreement. All
 *          key material lives in the PSA key store and is referenced through
 *          \c psa_key_id_t handles; no secret is exported to the caller. Access
 *          the vtables through \ref edhoc_cipher_suite_2_get_crypto and
 *          \ref edhoc_cipher_suite_2_get_suite (or the enum getters in
 *          \c <edhoc/cipher_suite.h>).
 *
 * @{
 */

/** 
 * \brief Get EDHOC crypto structure for cipher suite 2.
 *
 * Returns a pointer to the cryptographic operations structure implementing
 * cipher suite 2 algorithms (AES-CCM-16-64-128, SHA-256, P-256, ES256).
 *
 * \return Pointer to cipher suite 2 crypto operations structure.
 */
const struct edhoc_crypto *edhoc_cipher_suite_2_get_crypto(void);

/**
 * \brief Get EDHOC cipher suite descriptor for cipher suite 2.
 *
 * Returns a pointer to a pre-initialized \c struct \c edhoc_cipher_suite
 * holding the canonical algorithm parameters of cipher suite 2
 * (value 2, AES-CCM-16-64-128, SHA-256, P-256, ES256).
 *
 * \return Pointer to cipher suite 2 descriptor.
 */
const struct edhoc_cipher_suite *edhoc_cipher_suite_2_get_suite(void);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_2_H */
