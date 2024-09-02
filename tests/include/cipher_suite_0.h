/**
 * \file    cipher_suite_0.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 0 conatins:
 *            - AEAD algorithm                      = AES-CCM-16-64-128
 *            - hash algorithm                      = SHA-256
 *            - MAC length in bytes (Static DH)     = 8
 *            - key exchange algorithm (ECDH curve) = X25519
 *            - signature algorithm                 = EdDSA
 *
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_0_H
#define CIPHER_SUITE_0_H

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

/**
 * \brief Crypto key generation.
 */
int cipher_suite_0_key_import(void *user_context, enum edhoc_key_type key_type,
			      const uint8_t *raw_key, size_t raw_key_len,
			      void *kid);

/**
 * \brief Crypto key destroy.
 */
int cipher_suite_0_key_destroy(void *user_context, void *kid);

/**
 * \brief ECDH make key pair.
 */
int cipher_suite_0_make_key_pair(void *user_context, const void *key_id,
				 uint8_t *private_key, size_t private_key_size,
				 size_t *private_key_length,
				 uint8_t *public_key, size_t public_key_size,
				 size_t *public_key_length);

/**
 * \brief ECDH key agreement.
 */
int cipher_suite_0_key_agreement(void *user_context, const void *key_id,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length,
				 uint8_t *shared_secret,
				 size_t shared_secret_size,
				 size_t *shared_secret_length);

/**
 * \brief ECDSA signature.
 */
int cipher_suite_0_signature(void *user_context, const void *key_id,
			     const uint8_t *input, size_t input_length,
			     uint8_t *signature, size_t signature_size,
			     size_t *signature_length);

/**
 * \brief ECDSA signature verification.
 */
int cipher_suite_0_verify(void *user_context, const void *key_id,
			  const uint8_t *input, size_t input_length,
			  const uint8_t *signature, size_t signature_length);

/**
 * \brief HKDF extract.
 */
int cipher_suite_0_extract(void *user_context, const void *key_id,
			   const uint8_t *salt, size_t salt_len,
			   uint8_t *psuedo_random_key,
			   size_t psuedo_random_key_size,
			   size_t *psuedo_random_key_length);

/**
 * \brief HKDF expand.
 */
int cipher_suite_0_expand(void *user_context, const void *key_id,
			  const uint8_t *info, size_t info_length,
			  uint8_t *output_keying_material,
			  size_t output_keying_material_length);

/**
 * \brief AEAD encrypt.
 */
int cipher_suite_0_encrypt(void *user_context, const void *key_id,
			   const uint8_t *nonce, size_t nonce_length,
			   const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *plaintext, size_t plaintext_length,
			   uint8_t *ciphertext, size_t ciphertext_size,
			   size_t *ciphertext_length);

/**
 * \brief AEAD decrypt.
 */
int cipher_suite_0_decrypt(void *user_context, const void *key_id,
			   const uint8_t *nonce, size_t nonce_length,
			   const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *ciphertext, size_t ciphertext_length,
			   uint8_t *plaintext, size_t plaintext_size,
			   size_t *plaintext_length);

/**
 * \brief Hash function.
 */
int cipher_suite_0_hash(void *user_context, const uint8_t *input,
			size_t input_length, uint8_t *hash, size_t hash_size,
			size_t *hash_length);

#endif /* CIPHER_SUITE_0_H */
