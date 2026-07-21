/**
 * \file    edhoc_cipher_suite_0.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 0 contains:
 *            - AEAD algorithm                      = AES-CCM-16-64-128
 *            - hash algorithm                      = SHA-256
 *            - MAC length in bytes (Static DH)     = 8
 *            - key exchange algorithm (ECDH curve) = X25519
 *            - signature algorithm                 = EdDSA
 *
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_0_H
#define EDHOC_CIPHER_SUITE_0_H

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

/** \defgroup edhoc-cipher-suite-0-api EDHOC cipher suite 0 API
 *
 * \details Reference implementation of EDHOC cipher suite 0
 *          (X25519 / EdDSA / AES-CCM-16-64-128 / SHA-256). The ephemeral key
 *          exchange, key derivation, AEAD and hashing run on PSA crypto
 *          (mbedTLS): the ephemeral key exchange is a NIKE-as-KEM shim over
 *          X25519 (\c generate_key_pair / \c encapsulate / \c decapsulate) and
 *          static-DH authentication (methods 1/2/3) uses \c key_agreement.
 *          EdDSA (Ed25519) is provided by Compact25519 because mbedTLS/PSA has
 *          no software EdDSA: \c verify uses the peer's raw public key, while
 *          \c sign exports the private key from its PSA raw-data handle for the
 *          Compact25519 call and wipes the copy afterwards. Access the vtables
 *          through
 *          \ref edhoc_cipher_suite_0_get_crypto and
 *          \ref edhoc_cipher_suite_0_get_suite (or the enum getters in
 *          \c <edhoc/cipher_suite.h>).
 *
 * @{
 */

/** 
 * \brief Get EDHOC crypto structure for cipher suite 0.
 *
 * Returns a pointer to the cryptographic operations structure implementing
 * cipher suite 0 algorithms (AES-CCM-16-64-128, SHA-256, X25519, EdDSA).
 *
 * \return Pointer to cipher suite 0 crypto operations structure.
 */
const struct edhoc_crypto *edhoc_cipher_suite_0_get_crypto(void);

/**
 * \brief Get EDHOC cipher suite descriptor for cipher suite 0.
 *
 * Returns a pointer to a pre-initialized \c struct \c edhoc_cipher_suite
 * holding the canonical algorithm parameters of cipher suite 0
 * (value 0, AES-CCM-16-64-128, SHA-256, X25519, EdDSA).
 *
 * \return Pointer to cipher suite 0 descriptor.
 */
const struct edhoc_cipher_suite *edhoc_cipher_suite_0_get_suite(void);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_0_H */
