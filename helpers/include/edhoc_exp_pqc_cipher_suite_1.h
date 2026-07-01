/**
 * \file    edhoc_exp_pqc_cipher_suite_1.h
 * \author  Kamil Kielbasa
 * \brief   Experimental post-quantum cipher suite 1 (draft TBD1 from
 *          draft-spm-lake-pqsuites-02, ML-KEM-512 + ML-DSA-44) contains:
 *            - AEAD algorithm                      = AES-CCM-16-128-128
 *            - hash algorithm (key deriv.)         = SHAKE256
 *            - MAC length in bytes (Static DH)     = 16
 *            - key exchange algorithm (KEM)        = ML-KEM-512
 *            - signature algorithm                 = ML-DSA-44
 *            - application AEAD algorithm          = AES-CCM-16-64-128
 *            - application hash algorithm          = SHA-256
 *
 *          Key exchange uses a KEM procedure: \c encapsulate (Responder) and
 *          \c decapsulate (Initiator) replace \c key_agreement. See
 *          \ref struct edhoc_crypto_pqc.
 *
 *          Draft reference:
 *          https://datatracker.ietf.org/doc/html/draft-spm-lake-pqsuites-02
 *
 * \note    ML-KEM-512 and ML-DSA-44 use liboqs; AES-CCM uses PSA.
 *          SHAKE256 hash uses the liboqs public SHA-3 API. EDHOC_Extract and
 *          EDHOC_Expand are KMAC256 (RFC 9528 Section 4.1), computed by the
 *          backend-agnostic edhoc_kdf_kmac256() helper (XKCP SP800-185 by
 *          default, or a self-contained equivalent); no liboqs-internal Keccak
 *          symbol is used.
 *
 * \note    Key identifiers: ML-KEM and ML-DSA material is stored as
 *          #PSA_KEY_TYPE_RAW_DATA; symmetric keys use the usual PSA types.
 *          Callbacks receive a \c psa_key_id_t through \p key_id and export raw
 *          material when calling liboqs.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_EXP_PQC_CIPHER_SUITE_1_H
#define EDHOC_EXP_PQC_CIPHER_SUITE_1_H

/* Include files ----------------------------------------------------------- */

#include "edhoc_crypto.h"
#include "edhoc_values.h"

#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */

/** \defgroup edhoc-exp-pqc-cipher-suite-1-sizes ML-KEM-512 / ML-DSA-44 sizes
 * @{
 */

/** ML-KEM-512 encapsulation key (public key) length in bytes. */
#define EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN ((size_t)800)
/** ML-KEM-512 decapsulation key (private key) length in bytes. */
#define EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN ((size_t)1632)
/** ML-KEM-512 ciphertext length in bytes (transported in G_Y). */
#define EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN ((size_t)768)
/** ML-KEM-512 shared secret length in bytes (the EDHOC G_XY). */
#define EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN ((size_t)32)

/** ML-DSA-44 public (verification) key length in bytes. */
#define EDHOC_EXP_PQC_CS1_MLDSA44_PK_LEN ((size_t)1312)
/** ML-DSA-44 private (signing) key length in bytes. */
#define EDHOC_EXP_PQC_CS1_MLDSA44_SK_LEN ((size_t)2560)
/** ML-DSA-44 signature length in bytes. */
#define EDHOC_EXP_PQC_CS1_MLDSA44_SIG_LEN ((size_t)2420)

/** SHAKE256 output length in bytes (hash and KDF key material). */
#define EDHOC_EXP_PQC_CS1_HASH_LEN ((size_t)64)

/**@}*/

/* Module types and type definitions -------------------------------------- */

/** \defgroup edhoc-exp-pqc-cipher-suite-1-api Experimental PQC cipher suite 1 API
 * @{
 */

/**
 * \brief KEM-shaped EDHOC cryptographic operations for post-quantum suites.
 *
 * Proposed evolution of \c struct \c edhoc_crypto for cipher suites that use
 * a KEM instead of ECDH. ECDH suites can implement this vtable as NIKE-as-KEM.
 */
struct edhoc_crypto_pqc {
	/**
	 * \brief Generate an ephemeral KEM key pair (Initiator, message_1).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier from
	 *                                      \c import_key(\c EDHOC_KT_MAKE_KEY_PAIR).
	 * \param[out] private_key              ML-KEM decapsulation key.
	 * \param private_key_size              Size of the \p private_key buffer in bytes.
	 * \param[out] private_key_length       On success, the number of bytes that make up
	 *                                      the decapsulation key.
	 * \param[out] public_key               ML-KEM encapsulation key (sent in G_X).
	 * \param public_key_size               Size of the \p public_key buffer in bytes.
	 * \param[out] public_key_length        On success, the number of bytes that make up
	 *                                      the encapsulation key.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*make_key_pair)(void *user_context, const void *key_id,
			     uint8_t *private_key, size_t private_key_size,
			     size_t *private_key_length, uint8_t *public_key,
			     size_t public_key_size, size_t *public_key_length);

	/**
	 * \brief Encapsulate to a peer encapsulation key (Responder, message_2).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier (unused for encapsulate).
	 * \param[in] peer_public_key           Peer ML-KEM encapsulation key from G_X.
	 * \param peer_public_key_length        Size of the \p peer_public_key buffer in bytes.
	 * \param[out] ciphertext               KEM ciphertext (sent in G_Y).
	 * \param ciphertext_size               Size of the \p ciphertext buffer in bytes.
	 * \param[out] ciphertext_length        On success, the number of bytes that make up
	 *                                      the ciphertext.
	 * \param[out] shared_secret            KEM shared secret (G_XY).
	 * \param shared_secret_size            Size of the \p shared_secret buffer in bytes.
	 * \param[out] shared_secret_length     On success, the number of bytes that make up
	 *                                      the shared secret.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*encapsulate)(void *user_context, const void *key_id,
			   const uint8_t *peer_public_key,
			   size_t peer_public_key_length, uint8_t *ciphertext,
			   size_t ciphertext_size, size_t *ciphertext_length,
			   uint8_t *shared_secret, size_t shared_secret_size,
			   size_t *shared_secret_length);

	/**
	 * \brief Decapsulate a ciphertext (Initiator, after message_2).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier for the decapsulation key.
	 * \param[in] ciphertext                KEM ciphertext from G_Y.
	 * \param ciphertext_length             Size of the \p ciphertext buffer in bytes.
	 * \param[out] shared_secret            KEM shared secret (G_XY).
	 * \param shared_secret_size            Size of the \p shared_secret buffer in bytes.
	 * \param[out] shared_secret_length     On success, the number of bytes that make up
	 *                                      the shared secret.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*decapsulate)(void *user_context, const void *key_id,
			   const uint8_t *ciphertext, size_t ciphertext_length,
			   uint8_t *shared_secret, size_t shared_secret_size,
			   size_t *shared_secret_length);

	/**
	 * \brief Generate a digital signature (ML-DSA-44).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] input                     Input message to sign.
	 * \param input_length                  Size of the \p input buffer in bytes.
	 * \param[out] signature                Buffer where the signature is to be written.
	 * \param signature_size                Size of the \p signature buffer in bytes.
	 * \param[out] signature_length         On success, the number of bytes that make up
	 *                                      the signature.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*signature)(void *user_context, const void *key_id,
			 const uint8_t *input, size_t input_length,
			 uint8_t *signature, size_t signature_size,
			 size_t *signature_length);

	/**
	 * \brief Verify a digital signature (ML-DSA-44).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] input                     Input message to verify.
	 * \param input_length                  Size of the \p input buffer in bytes.
	 * \param[in] signature                 Buffer containing the signature to verify.
	 * \param signature_length              Size of the \p signature buffer in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*verify)(void *user_context, const void *key_id,
		      const uint8_t *input, size_t input_length,
		      const uint8_t *signature, size_t signature_length);

	/**
	 * \brief Perform EDHOC_Extract (KMAC256 for SHAKE256 suite, RFC 9528 §4.1.1).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] salt                      Salt for extract.
	 * \param salt_len                      Size of the \p salt buffer in bytes.
	 * \param[out] pseudo_random_key        Buffer where the pseudorandom key is to be written.
	 * \param pseudo_random_key_size        Size of the \p pseudo_random_key buffer in bytes.
	 * \param[out] pseudo_random_key_length On success, the number of bytes that make up
	 *                                      the pseudorandom key.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*extract)(void *user_context, const void *key_id,
		       const uint8_t *salt, size_t salt_len,
		       uint8_t *pseudo_random_key,
		       size_t pseudo_random_key_size,
		       size_t *pseudo_random_key_length);

	/**
	 * \brief Perform EDHOC_Expand (KMAC256 for SHAKE256 suite, RFC 9528 §4.1.2).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] info                      Context and application-specific information.
	 * \param info_length                   Size of the \p info buffer in bytes.
	 * \param[out] output_keying_material   Buffer where the output keying material is to be written.
	 * \param output_keying_material_length Size of the \p output_keying_material buffer in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*expand)(void *user_context, const void *key_id,
		      const uint8_t *info, size_t info_length,
		      uint8_t *output_keying_material,
		      size_t output_keying_material_length);

	/**
	 * \brief Perform AEAD encryption (AES-CCM-16-128-128).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] nonce                     Nonce or IV to use.
	 * \param nonce_length                  Size of the \p nonce buffer in bytes.
	 * \param[in] additional_data           Additional data that will be authenticated but not encrypted.
	 * \param additional_data_length        Size of the \p additional_data buffer in bytes.
	 * \param[in] plaintext                 Data that will be authenticated and encrypted.
	 * \param plaintext_length              Size of the \p plaintext buffer in bytes.
	 * \param[out] ciphertext               Buffer where the authenticated and encrypted data is to be written.
	 * \param ciphertext_size               Size of the \p ciphertext buffer in bytes.
	 * \param[out] ciphertext_length        On success, the number of bytes that make up the ciphertext.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*encrypt)(void *user_context, const void *key_id,
		       const uint8_t *nonce, size_t nonce_length,
		       const uint8_t *additional_data,
		       size_t additional_data_length, const uint8_t *plaintext,
		       size_t plaintext_length, uint8_t *ciphertext,
		       size_t ciphertext_size, size_t *ciphertext_length);

	/**
	 * \brief Perform AEAD decryption (AES-CCM-16-128-128).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] key_id                    Key identifier.
	 * \param[in] nonce                     Nonce or IV to use.
	 * \param nonce_length                  Size of the \p nonce buffer in bytes.
	 * \param[in] additional_data           Additional data that will be authenticated but not encrypted.
	 * \param additional_data_length        Size of the \p additional_data buffer in bytes.
	 * \param[in] ciphertext                Buffer containing the authenticated and encrypted data.
	 * \param ciphertext_length             Size of the \p ciphertext buffer in bytes.
	 * \param[out] plaintext                Buffer where the decrypted data is to be written.
	 * \param plaintext_size                Size of the \p plaintext buffer in bytes.
	 * \param[out] plaintext_length         On success, the number of bytes that make up the plaintext.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*decrypt)(void *user_context, const void *key_id,
		       const uint8_t *nonce, size_t nonce_length,
		       const uint8_t *additional_data,
		       size_t additional_data_length, const uint8_t *ciphertext,
		       size_t ciphertext_length, uint8_t *plaintext,
		       size_t plaintext_size, size_t *plaintext_length);

	/**
	 * \brief Compute the EDHOC hash (SHAKE256, 64-byte output).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] input                     Input message to hash.
	 * \param input_length                  Size of the \p input buffer in bytes.
	 * \param[out] hash                     Buffer where the hash is to be written.
	 * \param hash_size                     Size of the \p hash buffer in bytes.
	 * \param[out] hash_length              On success, the number of bytes that make up the hash.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*hash)(void *user_context, const uint8_t *input,
		    size_t input_length, uint8_t *hash, size_t hash_size,
		    size_t *hash_length);
};

/**
 * \brief Cipher-suite descriptor for KEM-based post-quantum suites.
 */
struct edhoc_cipher_suite_pqc {
	/** Cipher suite IANA registry value (not yet assigned; helper uses -1). */
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

	/** ML-KEM encapsulation key length in bytes. */
	size_t kem_public_key_length;
	/** ML-KEM decapsulation key length in bytes. */
	size_t kem_private_key_length;
	/** ML-KEM ciphertext length in bytes. */
	size_t kem_ciphertext_length;
	/** ML-KEM shared secret length in bytes. */
	size_t kem_shared_secret_length;

	/** ML-DSA signature length in bytes. */
	size_t signature_length;
};

/**
 * \brief Get the KEM-shaped crypto operations for experimental cipher suite 1.
 *
 * \return Pointer to the experimental PQC cipher suite 1 crypto operations structure.
 */
const struct edhoc_crypto_pqc *edhoc_exp_pqc_cipher_suite_1_get_crypto(void);

/**
 * \brief Get the key management operations for experimental cipher suite 1.
 *
 * \return Pointer to the experimental PQC cipher suite 1 keys operations structure.
 */
const struct edhoc_keys *edhoc_exp_pqc_cipher_suite_1_get_keys(void);

/**
 * \brief Get the cipher suite descriptor for experimental cipher suite 1.
 *
 * Returns a pointer to a pre-initialized \c struct \c edhoc_cipher_suite_pqc
 * holding the canonical algorithm parameters of experimental PQC cipher suite 1.
 *
 * \return Pointer to the experimental PQC cipher suite 1 descriptor.
 */
const struct edhoc_cipher_suite_pqc *
edhoc_exp_pqc_cipher_suite_1_get_suite(void);

/**@}*/

#endif /* EDHOC_EXP_PQC_CIPHER_SUITE_1_H */
