/**
 * \file    edhoc_cipher_suite_24.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 24 contains:
 *            - AEAD algorithm                      = A256GCM
 *            - hash algorithm                      = SHA-384
 *            - MAC length in bytes (Static DH)     = 16
 *            - key exchange algorithm (ECDH curve) = P-384
 *            - signature algorithm                 = ES384
 *
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_24_H
#define EDHOC_CIPHER_SUITE_24_H

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

/** \defgroup edhoc-cipher-suite-24-api EDHOC cipher suite 24 API
 *
 * \details Reference implementation of EDHOC cipher suite 24
 *          (P-384 / ES384 / A256GCM / SHA-384), built on PSA crypto (mbedTLS).
 *          The ephemeral key exchange is a NIKE-as-KEM shim over ECDH P-384
 *          (\c generate_key_pair / \c encapsulate / \c decapsulate); static-DH
 *          authentication (methods 1/2/3) uses \c key_agreement. Access the
 *          vtables through \ref edhoc_cipher_suite_24_get_crypto and
 *          \ref edhoc_cipher_suite_24_get_suite (or the enum getters in
 *          \c <edhoc/cipher_suite.h>).
 *
 * @{
 */

/** 
 * \brief Get EDHOC crypto structure for cipher suite 24.
 *
 * Returns a pointer to the cryptographic operations structure implementing
 * cipher suite 24 algorithms (A256GCM, SHA-384, P-384, ES384).
 *
 * \return Pointer to cipher suite 24 crypto operations structure.
 */
const struct edhoc_crypto *edhoc_cipher_suite_24_get_crypto(void);

/**
 * \brief Get EDHOC cipher suite descriptor for cipher suite 24.
 *
 * Returns a pointer to a pre-initialized \c struct \c edhoc_cipher_suite
 * holding the canonical algorithm parameters of cipher suite 24
 * (value 24, A256GCM, SHA-384, P-384, ES384).
 *
 * \return Pointer to cipher suite 24 descriptor.
 */
const struct edhoc_cipher_suite *edhoc_cipher_suite_24_get_suite(void);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_24_H */
