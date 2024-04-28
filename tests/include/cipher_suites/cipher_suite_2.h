/**
 * \file    cipher_suite_2.h
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 2 API:
 *            - AEAD algorithm                      = AES-CCM-16-64-128
 *            - hash algorithm                      = SHA-256
 *            - MAC length in bytes (Static DH)     = 8
 *            - key exchange algorithm (ECDH curve) = P-256
 *            - signature algorithm                 = ES256
 *
 * \version 0.2
 * \date    2024-04-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_2_H
#define CIPHER_SUITE_2_H

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

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/**
 * \brief Crypto key generation.
 */
int cipher_suite_2_key_generate(enum edhoc_key_type key_type,
				const uint8_t *raw_key, size_t raw_key_len,
				void *kid);

/**
 * \brief Crypto key destroy.
 */
int cipher_suite_2_key_destroy(void *kid);

/**
 * \brief ECDH make key pair.
 */
int cipher_suite_2_make_key_pair(const void *key_id,
				 uint8_t *restrict private_key,
				 size_t private_key_size,
				 size_t *restrict private_key_length,
				 uint8_t *restrict public_key,
				 size_t public_key_size,
				 size_t *restrict public_key_length);

/**
 * \brief ECDH key agreement.
 */
int cipher_suite_2_key_agreement(const void *key_id,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length,
				 uint8_t *shared_secret,
				 size_t shared_secret_size,
				 size_t *shared_secret_length);

/**
 * \brief ECDSA signature.
 */
int cipher_suite_2_signature(const void *key_id, const uint8_t *input,
			     size_t input_length, uint8_t *signature,
			     size_t signature_size, size_t *signature_length);

/**
 * \brief ECDSA signature verification.
 */
int cipher_suite_2_verify(const void *key_id, const uint8_t *input,
			  size_t input_length, const uint8_t *signature,
			  size_t signature_length);

/**
 * \brief HKDF extract.
 */
int cipher_suite_2_extract(const void *key_id, const uint8_t *salt,
			   size_t salt_len, uint8_t *psuedo_random_key,
			   size_t psuedo_random_key_size,
			   size_t *psuedo_random_key_length);

/**
 * \brief HKDF expand.
 */
int cipher_suite_2_expand(const void *key_id, const uint8_t *info,
			  size_t info_length, uint8_t *output_keying_material,
			  size_t output_keying_material_length);

/**
 * \brief AEAD encrypt.
 */
int cipher_suite_2_encrypt(const void *key_id, const uint8_t *nonce,
			   size_t nonce_length, const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *plaintext, size_t plaintext_length,
			   uint8_t *ciphertext, size_t ciphertext_size,
			   size_t *ciphertext_length);

/**
 * \brief AEAD decrypt.
 */
int cipher_suite_2_decrypt(const void *key_id, const uint8_t *nonce,
			   size_t nonce_length, const uint8_t *additional_data,
			   size_t additional_data_length,
			   const uint8_t *ciphertext, size_t ciphertext_length,
			   uint8_t *plaintext, size_t plaintext_size,
			   size_t *plaintext_length);

/**
 * \brief Hash function.
 */
int cipher_suite_2_hash(const uint8_t *input, size_t input_length,
			uint8_t *hash, size_t hash_size, size_t *hash_length);

#endif /* CIPHER_SUITE_2_H */
