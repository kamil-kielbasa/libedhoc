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
 * \copyright Copyright (c) 2026
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_24_H
#define EDHOC_CIPHER_SUITE_24_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include <edhoc/edhoc_crypto.h>

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
 * \details For ES384, \ref edhoc_cipher_suite_24_signature and \ref edhoc_cipher_suite_24_verify
 *          split a \c psa_sign_message-style operation into **hash, then sign**
 *          (\ref edhoc_cipher_suite_24_hash, then \c psa_sign_hash / \c psa_verify_hash with
 *          \c PSA_ALG_ECDSA(\c PSA_ALG_SHA_384)), so each step can follow your platform
 *          configuration. That helps when **moving a large message through the signing path is
 *          costly** (e.g. some secure elements). The \c input to those callbacks is still the full
 *          COSE Sign1 payload from the library, not an application-supplied digest.
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
 * \brief Get EDHOC keys structure for cipher suite 24.
 *
 * Returns a pointer to the key management operations structure implementing
 * cipher suite 24 key handling.
 *
 * \return Pointer to cipher suite 24 keys operations structure.
 */
const struct edhoc_keys *edhoc_cipher_suite_24_get_keys(void);

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

/** 
 * \brief Import cryptographic key into cipher suite 24.
 *
 * Imports a raw cryptographic key and associates it with a key identifier.
 * The key type determines the algorithm and usage context.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_type                 Type of cryptographic key to import.
 * \param[in] raw_key                  Buffer containing the raw key material.
 * \param raw_key_len                  Length of the \p raw_key buffer in bytes.
 * \param[out] kid                     Key identifier for the imported key.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Key import operation failed.
 */
int edhoc_cipher_suite_24_key_import(void *user_context,
				     enum edhoc_key_type key_type,
				     const uint8_t *raw_key, size_t raw_key_len,
				     void *kid);

/** 
 * \brief Destroy cryptographic key.
 *
 * Securely destroys a previously imported cryptographic key and releases
 * associated resources.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] kid                      Key identifier of the key to destroy.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Key destroy operation failed.
 */
int edhoc_cipher_suite_24_key_destroy(void *user_context, void *kid);

/** 
 * \brief Generate ECDH key pair using P-384.
 *
 * Generates an ephemeral Diffie-Hellman key pair for P-384 (secp384r1) elliptic curve.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier for the generated key pair.
 * \param[out] private_key             Buffer where the private key will be written.
 * \param private_key_size             Size of the \p private_key buffer in bytes.
 * \param[out] private_key_length      On success, length of the generated private key.
 * \param[out] public_key              Buffer where the public key will be written.
 * \param public_key_size              Size of the \p public_key buffer in bytes.
 * \param[out] public_key_length       On success, length of the generated public key.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Key pair generation failed.
 */
int edhoc_cipher_suite_24_make_key_pair(void *user_context, const void *key_id,
					uint8_t *restrict private_key,
					size_t private_key_size,
					size_t *restrict private_key_length,
					uint8_t *restrict public_key,
					size_t public_key_size,
					size_t *restrict public_key_length);

/** 
 * \brief Perform ECDH key agreement using P-384.
 *
 * Computes a shared secret using the local private key and the peer's public key
 * via P-384 (secp384r1) elliptic curve Diffie-Hellman.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the local private key.
 * \param[in] peer_public_key          Buffer containing the peer's public key.
 * \param peer_public_key_length       Length of the \p peer_public_key buffer in bytes.
 * \param[out] shared_secret           Buffer where the shared secret will be written.
 * \param shared_secret_size           Size of the \p shared_secret buffer in bytes.
 * \param[out] shared_secret_length    On success, length of the computed shared secret.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Key agreement computation failed.
 */
int edhoc_cipher_suite_24_key_agreement(void *user_context, const void *key_id,
					const uint8_t *peer_public_key,
					size_t peer_public_key_length,
					uint8_t *shared_secret,
					size_t shared_secret_size,
					size_t *shared_secret_length);

/** 
 * \brief Generate ES384 signature.
 *
 * Creates a digital signature over the input data using ES384 (ECDSA with P-384 and SHA-384).
 * Uses \ref edhoc_cipher_suite_24_hash for SHA-384, then \c psa_sign_hash (same outcome as
 * \c psa_sign_message with \c PSA_ALG_ECDSA(\c PSA_ALG_SHA_384); see module \details for rationale).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the signing key.
 * \param[in] input                    Buffer containing the full message to be signed (not a digest).
 * \param input_length                 Length of the \p input buffer in bytes.
 * \param[out] signature               Buffer where the signature will be written.
 * \param signature_size               Size of the \p signature buffer in bytes.
 * \param[out] signature_length        On success, length of the generated signature.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Signature generation failed.
 */
int edhoc_cipher_suite_24_signature(void *user_context, const void *key_id,
				    const uint8_t *input, size_t input_length,
				    uint8_t *signature, size_t signature_size,
				    size_t *signature_length);

/** 
 * \brief Verify ES384 signature.
 *
 * Verifies a digital signature over the input data using ES384 (ECDSA with P-384 and SHA-384).
 * Uses \ref edhoc_cipher_suite_24_hash for SHA-384, then \c psa_verify_hash (see module \details).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the verification key.
 * \param[in] input                    Buffer containing the full signed message (not a digest).
 * \param input_length                 Length of the \p input buffer in bytes.
 * \param[in] signature                Buffer containing the signature to verify.
 * \param signature_length             Length of the \p signature buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Signature verification succeeded.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Signature verification failed.
 */
int edhoc_cipher_suite_24_verify(void *user_context, const void *key_id,
				 const uint8_t *input, size_t input_length,
				 const uint8_t *signature,
				 size_t signature_length);

/** 
 * \brief HKDF extract using SHA-384.
 *
 * Performs the HKDF-Extract operation to derive a pseudorandom key from
 * input keying material using SHA-384 as the hash function.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the input keying material.
 * \param[in] salt                     Optional salt value (can be NULL).
 * \param salt_len                     Length of the \p salt buffer in bytes.
 * \param[out] pseudo_random_key       Buffer where the PRK will be written.
 * \param pseudo_random_key_size       Size of the \p pseudo_random_key buffer in bytes.
 * \param[out] pseudo_random_key_length On success, length of the generated PRK.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         HKDF-Extract operation failed.
 */
int edhoc_cipher_suite_24_extract(void *user_context, const void *key_id,
				  const uint8_t *salt, size_t salt_len,
				  uint8_t *pseudo_random_key,
				  size_t pseudo_random_key_size,
				  size_t *pseudo_random_key_length);

/** 
 * \brief HKDF expand using SHA-384.
 *
 * Performs the HKDF-Expand operation to derive output keying material from
 * a pseudorandom key using SHA-384 as the hash function.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the pseudorandom key (PRK).
 * \param[in] info                     Context and application specific information.
 * \param info_length                  Length of the \p info buffer in bytes.
 * \param[out] output_keying_material  Buffer where the OKM will be written.
 * \param output_keying_material_length Desired length of output keying material in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         HKDF-Expand operation failed.
 */
int edhoc_cipher_suite_24_expand(void *user_context, const void *key_id,
				 const uint8_t *info, size_t info_length,
				 uint8_t *output_keying_material,
				 size_t output_keying_material_length);

/** 
 * \brief AEAD encrypt using A256GCM.
 *
 * Encrypts plaintext using AES-GCM with a 256-bit key, 128-bit tag, and 12-byte nonce.
 * Provides authenticated encryption with associated data (AEAD).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the encryption key.
 * \param[in] nonce                    Nonce (12 bytes for A256GCM).
 * \param nonce_length                 Length of the \p nonce buffer in bytes.
 * \param[in] additional_data          Additional authenticated data (can be NULL).
 * \param additional_data_length       Length of the \p additional_data buffer in bytes.
 * \param[in] plaintext                Buffer containing plaintext to encrypt.
 * \param plaintext_length             Length of the \p plaintext buffer in bytes.
 * \param[out] ciphertext              Buffer where ciphertext and tag will be written.
 * \param ciphertext_size              Size of the \p ciphertext buffer in bytes.
 * \param[out] ciphertext_length       On success, length of ciphertext plus tag.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Encryption operation failed.
 */
int edhoc_cipher_suite_24_encrypt(void *user_context, const void *key_id,
				  const uint8_t *nonce, size_t nonce_length,
				  const uint8_t *additional_data,
				  size_t additional_data_length,
				  const uint8_t *plaintext,
				  size_t plaintext_length, uint8_t *ciphertext,
				  size_t ciphertext_size,
				  size_t *ciphertext_length);

/** 
 * \brief AEAD decrypt using A256GCM.
 *
 * Decrypts ciphertext using AES-GCM with a 256-bit key, 128-bit tag, and 12-byte nonce.
 * Provides authenticated decryption with associated data (AEAD).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the decryption key.
 * \param[in] nonce                    Nonce (12 bytes for A256GCM).
 * \param nonce_length                 Length of the \p nonce buffer in bytes.
 * \param[in] additional_data          Additional authenticated data (can be NULL).
 * \param additional_data_length       Length of the \p additional_data buffer in bytes.
 * \param[in] ciphertext               Buffer containing ciphertext and tag to decrypt.
 * \param ciphertext_length            Length of the \p ciphertext buffer in bytes (including tag).
 * \param[out] plaintext               Buffer where decrypted plaintext will be written.
 * \param plaintext_size               Size of the \p plaintext buffer in bytes.
 * \param[out] plaintext_length        On success, length of the decrypted plaintext.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Decryption or authentication failed.
 */
int edhoc_cipher_suite_24_decrypt(void *user_context, const void *key_id,
				  const uint8_t *nonce, size_t nonce_length,
				  const uint8_t *additional_data,
				  size_t additional_data_length,
				  const uint8_t *ciphertext,
				  size_t ciphertext_length, uint8_t *plaintext,
				  size_t plaintext_size,
				  size_t *plaintext_length);

/** 
 * \brief Compute SHA-384 hash.
 *
 * Computes the SHA-384 cryptographic hash of the input data.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] input                    Buffer containing data to hash.
 * \param input_length                 Length of the \p input buffer in bytes.
 * \param[out] hash                    Buffer where the hash will be written.
 * \param hash_size                    Size of the \p hash buffer in bytes (must be ≥ 48).
 * \param[out] hash_length             On success, length of the computed hash (48 bytes).
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Invalid input parameter.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Hash computation failed.
 */
int edhoc_cipher_suite_24_hash(void *user_context, const uint8_t *input,
			       size_t input_length, uint8_t *hash,
			       size_t hash_size, size_t *hash_length);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_24_H */
