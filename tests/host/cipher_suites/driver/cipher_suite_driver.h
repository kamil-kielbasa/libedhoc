/**
 * \file    cipher_suite_driver.h
 * \author  Kamil Kielbasa
 * \brief   Descriptor and shared helpers for the parametrized cipher-suite
 *          crypto tests.
 *
 *          Every reference cipher suite exposes the same crypto vtable
 *          (\ref edhoc_crypto) and the same algorithm-length descriptor
 *          (\ref edhoc_cipher_suite). Only the concrete algorithms differ
 *          (EdDSA vs ECDSA vs ML-DSA, AES-CCM vs ChaCha20-Poly1305 vs AES-GCM,
 *          HKDF vs KMAC256, SHA vs SHAKE256), so one \ref cipher_suite_descriptor
 *          plus a set of \c cipher_suite_test_* routines drives every suite's crypto
 *          tests; a per-suite file is just the descriptor and thin \c TEST()
 *          cases that delegate to those routines.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_DRIVER_H
#define CIPHER_SUITE_DRIVER_H

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/**
 * \brief How a signing private key is imported into the backend key store.
 */
enum cipher_suite_sign_import {
	/** Ed25519 seed || public key as an exportable RAW_DATA key. */
	CIPHER_SUITE_SIGN_ED25519,
	/** ECDSA over SHA-256 (ECC SECP_R1 sign-hash key). */
	CIPHER_SUITE_SIGN_ECDSA_SHA256,
	/** ECDSA over SHA-384 (ECC SECP_R1 sign-hash key). */
	CIPHER_SUITE_SIGN_ECDSA_SHA384,
	/** ML-DSA-44 key imported into the post-quantum software keystore. */
	CIPHER_SUITE_SIGN_ML_DSA_44,
};

/**
 * \brief Static Diffie-Hellman / ephemeral curve used by the key exchange.
 */
enum cipher_suite_nike_curve {
	/** No static-DH curve: the suite's key exchange is a KEM. */
	CIPHER_SUITE_NIKE_NONE,
	/** Curve25519 (X25519 key agreement, Montgomery family). */
	CIPHER_SUITE_NIKE_X25519,
	/** NIST P-256 (SECP_R1 key agreement). */
	CIPHER_SUITE_NIKE_P256,
	/** NIST P-384 (SECP_R1 key agreement). */
	CIPHER_SUITE_NIKE_P384,
};

/**
 * \brief AEAD algorithm the suite encrypts and decrypts with.
 */
enum cipher_suite_aead_import {
	/** AES-CCM with a shortened tag. */
	CIPHER_SUITE_AEAD_AES_CCM,
	/** ChaCha20-Poly1305. */
	CIPHER_SUITE_AEAD_CHACHA20_POLY1305,
	/** AES-GCM. */
	CIPHER_SUITE_AEAD_AES_GCM,
};

/**
 * \brief Key derivation function family the suite extracts and expands with.
 */
enum cipher_suite_kdf {
	/** HKDF with SHA-256. */
	CIPHER_SUITE_KDF_HKDF_SHA256,
	/** HKDF with SHA-384. */
	CIPHER_SUITE_KDF_HKDF_SHA384,
	/** KMAC256 (RFC 9528: 4.1.2), used by the post-quantum suite. */
	CIPHER_SUITE_KDF_KMAC256,
};

/**
 * \brief A read-only byte buffer referenced (not owned) by a descriptor.
 */
struct cipher_suite_vector {
	/** Pointer to the bytes. */
	const uint8_t *pointer;
	/** Number of bytes. */
	size_t length;
};

/**
 * \brief Everything the crypto tests need to know about one cipher suite.
 *
 *        The reference crypto vtable and parameters are looked up from the
 *        public \ref edhoc_cipher_suite_get_crypto / \ref
 *        edhoc_cipher_suite_get_params dispatchers keyed by \c id, so the whole
 *        descriptor is plain data.
 */
struct cipher_suite_descriptor {
	/** Suite identifier, e.g. \c EDHOC_CIPHER_SUITE_0. */
	enum edhoc_cipher_suite_id id;
	/** Human-readable suite name (diagnostics only). */
	const char *name;

	/** Canonical algorithm lengths, asserted against \c get_params(). */
	struct edhoc_cipher_suite expected;

	/** Signature: import flavor and the key pair. */
	struct {
		enum cipher_suite_sign_import import;
		struct cipher_suite_vector private_key;
		struct cipher_suite_vector public_key;
	} sign;

	/** Static Diffie-Hellman: curve and a fixed valid private key. */
	struct {
		enum cipher_suite_nike_curve curve;
		struct cipher_suite_vector private_key;
	} nike;

	/** AEAD algorithm the suite encrypts and decrypts with. */
	enum cipher_suite_aead_import aead;

	/** Key derivation: family and its known-answer test vectors. */
	struct {
		enum cipher_suite_kdf algorithm;
		struct cipher_suite_vector ikm;
		struct cipher_suite_vector salt;
		struct cipher_suite_vector info;
		struct cipher_suite_vector okm;
	} kdf;

	/** Hash known-answer test: input message and its expected digest. */
	struct {
		struct cipher_suite_vector input;
		struct cipher_suite_vector expected;
	} hash;

	/**
	 * \brief Optional import for an oversized signing key.
	 *
	 *        The post-quantum ML-DSA-44 key does not fit the PSA key store,
	 *        so that suite provides this hook to load it into its own
	 *        software keystore. When \c NULL, the driver imports the signing
	 *        key through PSA per \c sign.import.
	 */
	int (*import_signing_key)(const uint8_t *signing_key,
				  size_t signing_key_length, void *key_id);
};

/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Import a signing private key per \c suite->sign.import (or the
 *        \c suite->import_signing_key hook when set).
 *
 * \param[in] suite             Suite descriptor.
 * \param[in] key               Private key bytes in the suite's import form.
 * \param key_length            Size of \p key in bytes.
 *
 * \return The backend key handle (the test aborts on a failed import).
 */
psa_key_id_t
cipher_suite_import_sign_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length);

/**
 * \brief Import a static-DH / ephemeral private key per \c suite->nike.curve.
 */
psa_key_id_t
cipher_suite_import_nike_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length);

/**
 * \brief Import key-derivation input material per \c suite->kdf.algorithm.
 */
psa_key_id_t
cipher_suite_import_kdf_key(const struct cipher_suite_descriptor *suite,
			    const uint8_t *key, size_t key_length);

/**
 * \brief Import an AEAD key per \c suite->aead.
 */
psa_key_id_t
cipher_suite_import_aead_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length);

#endif /* CIPHER_SUITE_DRIVER_H */
