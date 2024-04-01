/**
 * @file    test_credentials.h
 * @author  Kamil Kielbasa
 * @brief   Test crypto for EDHOC.
 *
 *          Implemented cipher suite number 2 which contains:
 *            AEAD algorithm                      = AES-CCM-16-64-128
 *            hash algorithm                      = SHA-256
 *            MAC length in bytes (Static DH)     = 8
 *            key exchange algorithm (ECDH curve) = P-256
 *            signature algorithm                 = ES256
 *
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_CRYPTO_H
#define TEST_CRYPTO_H

/* Include files ----------------------------------------------------------- */
#include "edhoc_crypto.h"

/* standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief EDHOC key generation.
 */
int edhoc_keys_generate(enum edhoc_key_type key_type, const uint8_t *raw_key,
			size_t raw_key_len, void *kid);

/**
 * \brief EDHOC key destroy.
 */
int edhoc_keys_destroy(void *kid);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - initiator side.
 *        - X509 chain authentication method.
 */
int test_crypto_make_key_pair_init_mocked_x509_chain(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - responder side.
 *        - X509 chain authentication method.
 */
int test_crypto_make_key_pair_resp_mocked_x509_chain(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - initiator side.
 *        - X509 hash authentication method.
 */
int test_crypto_make_key_pair_init_mocked_x509_hash(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - responder side.
 *        - X509 hash authentication method.
 */
int test_crypto_make_key_pair_resp_mocked_x509_hash(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - initiator side.
 *        - X509 kid authentication method.
 */
int test_crypto_make_key_pair_init_mocked_x509_kid(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair:
 *        - responder side.
 *        - X509 kid authentication method.
 */
int test_crypto_make_key_pair_resp_mocked_x509_kid(
	const void *kid, uint8_t *priv_key, size_t priv_key_size,
	size_t *priv_key_len, uint8_t *pub_key, size_t pub_key_size,
	size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH make key pair.
 */
int test_crypto_make_key_pair(const void *kid, uint8_t *priv_key,
			      size_t priv_key_size, size_t *priv_key_len,
			      uint8_t *pub_key, size_t pub_key_size,
			      size_t *pub_key_len);

/**
 * \brief EDHOC crypto function for ECDH key agreement.
 */
int test_crypto_key_agreement(const void *kid, const uint8_t *peer_key,
			      size_t peer_key_len, uint8_t *shared_secret,
			      size_t shared_secret_size,
			      size_t *shared_secret_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - initiator side.
 *        - X509 chain authentication method.
 */
int test_crypto_sign_init_mocked_x509_chain(const void *kid,
					    const uint8_t *input,
					    size_t input_len, uint8_t *sign,
					    size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - responder side.
 *        - X509 chain authentication method.
 */
int test_crypto_sign_resp_mocked_x509_chain(const void *kid,
					    const uint8_t *input,
					    size_t input_len, uint8_t *sign,
					    size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - initiator side.
 *        - X509 hash authentication method.
 */
int test_crypto_sign_init_mocked_x509_hash(const void *kid,
					   const uint8_t *input,
					   size_t input_len, uint8_t *sign,
					   size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - responder side.
 *        - X509 hash authentication method.
 */
int test_crypto_sign_resp_mocked_x509_hash(const void *kid,
					   const uint8_t *input,
					   size_t input_len, uint8_t *sign,
					   size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - initiator side.
 *        - X509 kid authentication method.
 */
int test_crypto_sign_init_mocked_x509_kid(const void *kid, const uint8_t *input,
					  size_t input_len, uint8_t *sign,
					  size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature:
 *        - responder side.
 *        - X509 kid authentication method.
 */
int test_crypto_sign_resp_mocked_x509_kid(const void *kid, const uint8_t *input,
					  size_t input_len, uint8_t *sign,
					  size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA signature.
 */
int test_crypto_sign(const void *kid, const uint8_t *input, size_t input_len,
		     uint8_t *sign, size_t sign_size, size_t *sign_len);

/**
 * \brief EDHOC crypto function for ECDSA verification.
 */
int test_crypto_verify(const void *kid, const uint8_t *input,
		       size_t intput_length, const uint8_t *sign,
		       size_t sign_len);

/**
 * \brief EDHOC crypto function for HKDF extract.
 */
int test_crypto_extract(const void *kid, const uint8_t *salt, size_t salt_len,
			uint8_t *prk, size_t prk_size, size_t *prk_len);

/**
 * \brief EDHOC crypto function for HKDF expand.
 */
int test_crypto_expand(const void *kid, const uint8_t *info, size_t info_len,
		       uint8_t *okm, size_t okm_len);

/**
 * \brief EDHOC crypto function for AEAD encrypt.
 */
int test_crypto_encrypt(const void *kid, const uint8_t *iv, size_t iv_len,
			const uint8_t *ad, size_t ad_len, const uint8_t *ptxt,
			size_t ptxt_len, uint8_t *ctxt, size_t ctext_size,
			size_t *ctxt_len);

/**
 * \brief EDHOC crypto function for AEAD decrypt.
 */
int test_crypto_decrypt(const void *kid, const uint8_t *iv, size_t iv_len,
			const uint8_t *ad, size_t ad_len, const uint8_t *ctxt,
			size_t ctxt_len, uint8_t *ptxt, size_t ptxt_size,
			size_t *ptxt_len);

/**
 * \brief EDHOC crypto function for hash.
 */
int test_crypto_hash(const uint8_t *input, size_t input_len, uint8_t *hash,
		     size_t hash_size, size_t *hash_len);

#endif /* TEST_CRYPTO_H */