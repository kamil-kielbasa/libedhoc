/**
 * \file    cipher_suite.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC cipher suite parameters and lookup of the bundled reference
 *          cipher suites.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_H
#define EDHOC_CIPHER_SUITE_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declarations ---------------------------------------------------- */

/** \brief Cryptographic operations vtable (see crypto.h). */
struct edhoc_crypto;

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-cipher-suite EDHOC cipher suite
 * @{
 */

/**
 * \brief Cipher suite value and the byte lengths of its algorithms.
 *
 *        Generalized for both NIKE (classical Diffie-Hellman) and KEM
 *        (e.g. ML-KEM) key exchange. For a classical suite the ephemeral leg
 *        is a NIKE-as-KEM shim, so the encapsulation key, the ciphertext and
 *        the static-DH key all share the elliptic-curve public-key length.
 */
struct edhoc_cipher_suite {
	/** Cipher suite IANA registry value. */
	int32_t value;

	/** Whether the suite provides static Diffie-Hellman authentication
	 *  (RFC 9528: 3.2, methods 1/2/3); method 0 (signatures only) needs no
	 *  static DH and is always available. */
	bool supports_dh_nike;

	/** Key exchange: encapsulation key (\c G_X) length in bytes. */
	size_t kem_encapsulation_key_length;
	/** Key exchange: ciphertext (\c G_Y) length in bytes. */
	size_t kem_ciphertext_length;
	/** Static-DH authentication key length in bytes; 0 if unsupported. */
	size_t nike_key_length;

	/** Signature length in bytes. */
	size_t sign_length;

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
	/** X25519 / EdDSA / ChaCha20-Poly1305 / SHA-256. */
	EDHOC_CIPHER_SUITE_4 = 4,
	/** P-384 / ES384 / A256GCM / SHA-384. */
	EDHOC_CIPHER_SUITE_24 = 24,
	/** ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256. */
	EDHOC_CIPHER_SUITE_PQC_1 = -24,
};

/**@}*/

/** \defgroup edhoc-cipher-suite-getters EDHOC cipher suite getters
 *
 * Look up the parameters and reference crypto backend of a bundled suite by its
 * \ref edhoc_cipher_suite_id, to pass to \ref edhoc_set_cipher_suites and
 * \ref edhoc_bind_crypto.
 * @{
 */

/**
 * \brief Look up the algorithm lengths of a cipher suite.
 *
 * Available for every identifier in \ref edhoc_cipher_suite_id: the lengths are
 * plain data with no build-time dependency.
 *
 * \param id                            Cipher suite identifier.
 *
 * \return Pointer to the statically allocated cipher suite parameters, or NULL
 *         if \p id is not a known suite.
 */
const struct edhoc_cipher_suite *
edhoc_cipher_suite_get_params(enum edhoc_cipher_suite_id id);

/**
 * \brief Look up the reference cryptographic operations of a cipher suite.
 *
 * Unlike \ref edhoc_cipher_suite_get_params, a reference crypto backend exists
 * only when its suite is enabled in the build configuration.
 *
 * \param id                            Cipher suite identifier.
 *
 * \return Pointer to the statically allocated crypto vtable, or NULL if \p id is
 *         unknown or its reference backend is not compiled in.
 */
const struct edhoc_crypto *
edhoc_cipher_suite_get_crypto(enum edhoc_cipher_suite_id id);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_H */
