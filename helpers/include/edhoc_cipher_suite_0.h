/**
 * \file    edhoc_cipher_suite_0.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 0 conatins:
 *            - AEAD algorithm                      = AES-CCM-16-64-128
 *            - hash algorithm                      = SHA-256
 *            - MAC length in bytes (Static DH)     = 8
 *            - key exchange algorithm (ECDH curve) = X25519
 *            - signature algorithm                 = EdDSA
 *
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_0_H
#define EDHOC_CIPHER_SUITE_0_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "edhoc_crypto.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/** \defgroup edhoc-cipher-suite-0-api EDHOC cipher suite 0 API
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
 * \brief Get EDHOC keys structure for cipher suite 0.
 *
 * Returns a pointer to the key management operations structure implementing
 * cipher suite 0 key handling.
 *
 * \return Pointer to cipher suite 0 keys operations structure.
 */
const struct edhoc_keys *edhoc_cipher_suite_0_get_keys(void);

/** 
 * \brief Import cryptographic key into cipher suite 0.
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
int edhoc_cipher_suite_0_key_import(void *user_context,
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
int edhoc_cipher_suite_0_key_destroy(void *user_context, void *kid);

/** 
 * \brief Generate ECDH key pair using X25519.
 *
 * Generates an ephemeral Diffie-Hellman key pair for X25519 elliptic curve.
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
int edhoc_cipher_suite_0_make_key_pair(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/** 
 * \brief Perform ECDH key agreement using X25519.
 *
 * Computes a shared secret using the local private key and the peer's public key
 * via X25519 elliptic curve Diffie-Hellman.
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
int edhoc_cipher_suite_0_key_agreement(void *user_context, const void *key_id,
				       const uint8_t *peer_public_key,
				       size_t peer_public_key_length,
				       uint8_t *shared_secret,
				       size_t shared_secret_size,
				       size_t *shared_secret_length);

/** 
 * \brief Generate EdDSA signature.
 *
 * Creates a digital signature over the input data using EdDSA (Ed25519).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the signing key.
 * \param[in] input                    Buffer containing data to be signed.
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
int edhoc_cipher_suite_0_signature(void *user_context, const void *key_id,
				   const uint8_t *input, size_t input_length,
				   uint8_t *signature, size_t signature_size,
				   size_t *signature_length);

/** 
 * \brief Verify EdDSA signature.
 *
 * Verifies a digital signature over the input data using EdDSA (Ed25519).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the verification key.
 * \param[in] input                    Buffer containing signed data.
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
int edhoc_cipher_suite_0_verify(void *user_context, const void *key_id,
				const uint8_t *input, size_t input_length,
				const uint8_t *signature,
				size_t signature_length);

/** 
 * \brief HKDF extract using SHA-256.
 *
 * Performs the HKDF-Extract operation to derive a pseudorandom key from
 * input keying material using SHA-256 as the hash function.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the input keying material.
 * \param[in] salt                     Optional salt value (can be NULL).
 * \param salt_len                     Length of the \p salt buffer in bytes.
 * \param[out] psuedo_random_key       Buffer where the PRK will be written.
 * \param psuedo_random_key_size       Size of the \p psuedo_random_key buffer in bytes.
 * \param[out] psuedo_random_key_length On success, length of the generated PRK.
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
int edhoc_cipher_suite_0_extract(void *user_context, const void *key_id,
				 const uint8_t *salt, size_t salt_len,
				 uint8_t *psuedo_random_key,
				 size_t psuedo_random_key_size,
				 size_t *psuedo_random_key_length);

/** 
 * \brief HKDF expand using SHA-256.
 *
 * Performs the HKDF-Expand operation to derive output keying material from
 * a pseudorandom key using SHA-256 as the hash function.
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
int edhoc_cipher_suite_0_expand(void *user_context, const void *key_id,
				const uint8_t *info, size_t info_length,
				uint8_t *output_keying_material,
				size_t output_keying_material_length);

/** 
 * \brief AEAD encrypt using AES-CCM-16-64-128.
 *
 * Encrypts plaintext using AES-CCM with 128-bit key, 64-bit tag, and 13-byte nonce.
 * Provides authenticated encryption with associated data (AEAD).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the encryption key.
 * \param[in] nonce                    Nonce (13 bytes for AES-CCM-16-64-128).
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
int edhoc_cipher_suite_0_encrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *plaintext,
				 size_t plaintext_length, uint8_t *ciphertext,
				 size_t ciphertext_size,
				 size_t *ciphertext_length);

/** 
 * \brief AEAD decrypt using AES-CCM-16-64-128.
 *
 * Decrypts ciphertext using AES-CCM with 128-bit key, 64-bit tag, and 13-byte nonce.
 * Provides authenticated decryption with associated data (AEAD).
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] key_id                   Key identifier of the decryption key.
 * \param[in] nonce                    Nonce (13 bytes for AES-CCM-16-64-128).
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
int edhoc_cipher_suite_0_decrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *ciphertext,
				 size_t ciphertext_length, uint8_t *plaintext,
				 size_t plaintext_size,
				 size_t *plaintext_length);

/** 
 * \brief Compute SHA-256 hash.
 *
 * Computes the SHA-256 cryptographic hash of the input data.
 *
 * \param[in] user_context             User-provided context pointer.
 * \param[in] input                    Buffer containing data to hash.
 * \param input_length                 Length of the \p input buffer in bytes.
 * \param[out] hash                    Buffer where the hash will be written.
 * \param hash_size                    Size of the \p hash buffer in bytes (must be ≥ 32).
 * \param[out] hash_length             On success, length of the computed hash (32 bytes).
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
int edhoc_cipher_suite_0_hash(void *user_context, const uint8_t *input,
			      size_t input_length, uint8_t *hash,
			      size_t hash_size, size_t *hash_length);

/**@}*/

#endif /* EDHOC_CIPHER_SUITE_0_H */
