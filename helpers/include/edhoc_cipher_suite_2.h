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
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_SUITE_2_H
#define EDHOC_CIPHER_SUITE_2_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "edhoc_crypto.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
#define ECC_COMP_KEY_LEN (32)
#define ECC_UNCOMP_KEY_LEN (65)

#define ECC_ECDSA_SIGN_LEN (64)
#define ECC_ECDH_KEY_AGREEMENT_LEN (32)

#define AEAD_TAG_LEN (8)
#define AEAD_KEY_LEN (16)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/**
 * \brief Crypto key generation.
 */
int edhoc_cipher_suite_2_key_import(void *user_context, enum edhoc_key_type key_type,
			      const uint8_t *raw_key, size_t raw_key_len,
			      void *kid);

/**
 * \brief Crypto key destroy.
 */
int edhoc_cipher_suite_2_key_destroy(void *user_context, void *kid);

/**
 * \brief ECDH make key pair.
 */
int edhoc_cipher_suite_2_make_key_pair(void *user_context, const void *key_id,
				 uint8_t *restrict private_key,
				 size_t private_key_size,
				 size_t *restrict private_key_length,
				 uint8_t *restrict public_key,
				 size_t public_key_size,
				 size_t *restrict public_key_length);

/**
 * \brief ECDH key agreement.
 */
int edhoc_cipher_suite_2_key_agreement(void *user_context, const void *key_id,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length,
				 uint8_t *shared_secret,
				 size_t shared_secret_size,
				 size_t *shared_secret_length);

/**
 * \brief ECDSA signature.
 */
int edhoc_cipher_suite_2_signature(void *user_context, const void *key_id,
			     const uint8_t *input, size_t input_length,
			     uint8_t *signature, size_t signature_size,
			     size_t *signature_length);

/**
 * \brief ECDSA signature verification.
 */
int edhoc_cipher_suite_2_verify(void *user_context, const void *key_id,
			  const uint8_t *input, size_t input_length,
			  const uint8_t *signature, size_t signature_length);

/**
 * \brief HKDF extract.
 */
int edhoc_cipher_suite_2_extract(void *user_context, const void *key_id,
			   const uint8_t *salt, size_t salt_len,
			   uint8_t *psuedo_random_key,
			   size_t psuedo_random_key_size,
			   size_t *psuedo_random_key_length);

/**
 * \brief HKDF expand.
 */
int edhoc_cipher_suite_2_expand(void *user_context, const void *key_id,
			  const uint8_t *info, size_t info_length,
			  uint8_t *output_keying_material,
			  size_t output_keying_material_length);

/**
 * \brief AEAD encrypt.
 */
int edhoc_cipher_suite_2_encrypt(void *user_context, const void *key_id,
			   const uint8_t *nonce, size_t nonce_length,
			   const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *plaintext, size_t plaintext_length,
			   uint8_t *ciphertext, size_t ciphertext_size,
			   size_t *ciphertext_length);

/**
 * \brief AEAD decrypt.
 */
int edhoc_cipher_suite_2_decrypt(void *user_context, const void *key_id,
			   const uint8_t *nonce, size_t nonce_length,
			   const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *ciphertext, size_t ciphertext_length,
			   uint8_t *plaintext, size_t plaintext_size,
			   size_t *plaintext_length);

/**
 * \brief Hash function.
 */
int edhoc_cipher_suite_2_hash(void *user_context, const uint8_t *input,
			size_t input_length, uint8_t *hash, size_t hash_size,
			size_t *hash_length);

/**
 * \brief Get EDHOC crypto structure for cipher suite 2.
 */
extern const struct edhoc_crypto *edhoc_cipher_suite_2_get_crypto(void);

#endif /* EDHOC_CIPHER_SUITE_2_H */

