/**
 * \file    edhoc_cipher_suite.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC cipher suite parameters and reference-implementation getters.
 *
 * \copyright Copyright (c) 2025
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_H
#define EDHOC_CIPHER_SUITE_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Forward declarations ---------------------------------------------------- */

/** \brief Cryptographic operations vtable (see edhoc_crypto.h). */
struct edhoc_crypto;

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-cipher-suite EDHOC cipher suite
 * @{
 */

/**
 * \brief Structure for cipher suite value and related algorithms lengths in bytes.
 */
struct edhoc_cipher_suite {
	/** Cipher suite IANA registry value. */
	int32_t value;

	/** EDHOC AEAD algorithm key length in bytes. */
	size_t aead_key_length;
	/** EDHOC AEAD algorithm tag length in bytes. */
	size_t aead_tag_length;
	/** EDHOC AEAD algorithm iv length in bytes. */
	size_t aead_iv_length;

	/** EDHOC hash algorithm: hash length in bytes. */
	size_t hash_length;

	/** EDHOC MAC length in bytes. */
	size_t mac_length;

	/** EDHOC ECC algorithm: key length in bytes. */
	size_t ecc_key_length;
	/** EDHOC ECC algorithm: signature length in bytes. */
	size_t ecc_sign_length;
};

/**
 * \brief Identifiers of the cipher suites shipped as reference implementations.
 *
 * The enum tag differs from the \ref edhoc_cipher_suite struct tag on purpose:
 * struct and enum share the C tag namespace.
 */
enum edhoc_cipher_suite_id {
	/** X25519 / EdDSA / AES-CCM-16-64-128 / SHA-256. */
	EDHOC_CIPHER_SUITE_0 = 0,
	/** P-256 / ES256 / AES-CCM-16-64-128 / SHA-256. */
	EDHOC_CIPHER_SUITE_2 = 2,
	/** P-384 / ES384 / A256GCM / SHA-384. */
	EDHOC_CIPHER_SUITE_24 = 24,
	/** Experimental ML-KEM + ML-DSA (private-use range until IANA assignment). */
	EDHOC_CIPHER_SUITE_PQC_1 = -24,
};

/**@}*/

/** \defgroup edhoc-cipher-suite-getters EDHOC cipher suite getters
 * @{
 */

/**
 * \brief Get the algorithm-length parameters of a cipher suite.
 *
 * Works for every known suite regardless of Kconfig (sizes are plain data with
 * no dependencies).
 *
 * \param id                            Cipher suite identifier.
 *
 * \return Pointer to the cipher suite parameters, or NULL if \p id is unknown.
 */
const struct edhoc_cipher_suite *
edhoc_cipher_suite_get_params(enum edhoc_cipher_suite_id id);

/**
 * \brief Get the reference cryptographic operations of a cipher suite.
 *
 * \param id                            Cipher suite identifier.
 *
 * \return Pointer to the cipher suite crypto vtable, or NULL unless the suite
 *         is compiled in.
 */
const struct edhoc_crypto *
edhoc_cipher_suite_get_crypto(enum edhoc_cipher_suite_id id);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_H */
