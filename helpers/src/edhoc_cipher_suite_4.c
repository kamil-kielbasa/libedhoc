/**
 * \file    edhoc_cipher_suite_4.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of cipher suite 4.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Include files ----------------------------------------------------------- */
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Internal test header: */
#include "edhoc_cipher_suite_4.h"

/* Standard library header: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* EDHOC headers: */
#include "edhoc_crypto.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"
#include "edhoc_backend_log.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Compact25519 crypto headers: */
#include <c25519/c25519.h>
#include <compact_x25519.h>
#include <compact_ed25519.h>

/* Module defines ---------------------------------------------------------- */
#define EDHOC_CIPHER_SUITE_4_VALUE (4)

#define EDHOC_CIPHER_SUITE_4_ECC_KEY_LEN (32)
#define EDHOC_CIPHER_SUITE_4_ECC_SIGN_LEN (64)

#define EDHOC_CIPHER_SUITE_4_HASH_LEN (32)
#define EDHOC_CIPHER_SUITE_4_MAC_LEN (16)

#define EDHOC_CIPHER_SUITE_4_AEAD_KEY_LEN (32)
#define EDHOC_CIPHER_SUITE_4_AEAD_TAG_LEN (16)
#define EDHOC_CIPHER_SUITE_4_AEAD_IV_LEN (12)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */

/* Module interface function definitions ----------------------------------- */

int edhoc_cipher_suite_4_key_import(void *user_ctx,
				    enum edhoc_key_type key_type,
				    const uint8_t *raw_key, size_t raw_key_len,
				    void *kid)
{
	(void)user_ctx;

	/*
         * 1. Generate key attr
         */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	switch (key_type) {
	case EDHOC_KT_MAKE_KEY_PAIR:
		return EDHOC_SUCCESS;

	case EDHOC_KT_KEY_AGREEMENT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr,
				 (size_t)PSA_BYTES_TO_BITS(X25519_SHARED_SIZE));
		break;

	case EDHOC_KT_SIGNATURE:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(
						ED25519_PRIVATE_KEY_SIZE));
		break;

	case EDHOC_KT_VERIFY:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(
						ED25519_PUBLIC_KEY_SIZE));
		break;

	case EDHOC_KT_EXTRACT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr,
				      PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_EXPAND:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr,
				      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_ENCRYPT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
		psa_set_key_algorithm(
			&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
				       PSA_ALG_CHACHA20_POLY1305,
				       EDHOC_CIPHER_SUITE_4_AEAD_TAG_LEN));
		psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
		psa_set_key_bits(&attr,
				 (size_t)PSA_BYTES_TO_BITS(
					 EDHOC_CIPHER_SUITE_4_AEAD_KEY_LEN));
		break;

	case EDHOC_KT_DECRYPT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(
			&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
				       PSA_ALG_CHACHA20_POLY1305,
				       EDHOC_CIPHER_SUITE_4_AEAD_TAG_LEN));
		psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
		psa_set_key_bits(&attr,
				 (size_t)PSA_BYTES_TO_BITS(
					 EDHOC_CIPHER_SUITE_4_AEAD_KEY_LEN));
		break;

	default:
		EDHOC_LOG_ERR("Unknown key type: %d", key_type);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/*
         * 2. Import key identifier
         */
	psa_key_id_t *psa_kid = kid;
	*psa_kid = PSA_KEY_HANDLE_INIT;

	const psa_status_t ret =
		psa_import_key(&attr, raw_key, raw_key_len, psa_kid);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import key: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_key_destroy(void *user_ctx, void *kid)
{
	(void)user_ctx;

	if (NULL == kid) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_key_id_t *psa_kid = kid;
	const psa_status_t ret = psa_destroy_key(*psa_kid);
	*psa_kid = PSA_KEY_HANDLE_INIT;

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Destroy key: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_make_key_pair(void *user_ctx, const void *kid,
				       uint8_t *priv_key, size_t priv_key_size,
				       size_t *priv_key_len, uint8_t *pub_key,
				       size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (priv_key_size < X25519_KEY_SIZE || pub_key_size < X25519_KEY_SIZE) {
		EDHOC_LOG_ERR("Invalid key sizes: %zu, %zu", priv_key_size,
			      pub_key_size);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	uint8_t seed[X25519_KEY_SIZE] = { 0 };
	const psa_status_t ret = psa_generate_random(seed, sizeof(seed));

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Generate random: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	compact_x25519_keygen(priv_key, pub_key, seed);
	*priv_key_len = X25519_KEY_SIZE;
	*pub_key_len = X25519_KEY_SIZE;

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_key_agreement(void *user_ctx, const void *kid,
				       const uint8_t *peer_pub_key,
				       size_t peer_pub_key_len,
				       uint8_t *shr_sec, size_t shr_sec_size,
				       size_t *shr_sec_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == peer_pub_key || 0 == peer_pub_key_len ||
	    NULL == shr_sec || 0 == shr_sec_size || NULL == shr_sec_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (X25519_KEY_SIZE != peer_pub_key_len ||
	    X25519_SHARED_SIZE != shr_sec_size) {
		EDHOC_LOG_ERR("Invalid key sizes: %zu, %zu", peer_pub_key_len,
			      shr_sec_size);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t priv_key_len = 0;
	uint8_t priv_key[X25519_KEY_SIZE] = { 0 };

	const psa_key_id_t *psa_kid = kid;
	const psa_status_t ret = psa_export_key(
		*psa_kid, priv_key, ARRAY_SIZE(priv_key), &priv_key_len);

	if (PSA_SUCCESS != ret || ARRAY_SIZE(priv_key) != priv_key_len) {
		EDHOC_LOG_ERR("Export private key: %d, %zu", ret, priv_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	uint8_t e[F25519_SIZE] = { 0 };
	f25519_copy(e, priv_key);
	c25519_prepare(e);
	c25519_smult(shr_sec, peer_pub_key, e);

	*shr_sec_len = X25519_SHARED_SIZE;

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_signature(void *user_ctx, const void *kid,
				   const uint8_t *input, size_t input_len,
				   uint8_t *sign, size_t sign_size,
				   size_t *sign_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == input || 0 == input_len || NULL == sign ||
	    0 == sign_size || NULL == sign_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ED25519_SIGNATURE_SIZE != sign_size) {
		EDHOC_LOG_ERR("Invalid signature size: %zu, %d", sign_size,
			      ED25519_SIGNATURE_SIZE);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t priv_key_len = 0;
	uint8_t priv_key[ED25519_PRIVATE_KEY_SIZE] = { 0 };

	const psa_key_id_t *psa_kid = kid;
	const psa_status_t ret = psa_export_key(
		*psa_kid, priv_key, ARRAY_SIZE(priv_key), &priv_key_len);

	if (PSA_SUCCESS != ret || ARRAY_SIZE(priv_key) != priv_key_len) {
		EDHOC_LOG_ERR("Export private key: %d, %zu", ret, priv_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	compact_ed25519_sign(sign, priv_key, input, input_len);
	*sign_len = ED25519_SIGNATURE_SIZE;

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_verify(void *user_ctx, const void *kid,
				const uint8_t *input, size_t input_len,
				const uint8_t *sign, size_t sign_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == input || 0 == input_len || NULL == sign ||
	    0 == sign_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ED25519_SIGNATURE_SIZE != sign_len) {
		EDHOC_LOG_ERR("Invalid signature size: %zu, %d", sign_len,
			      ED25519_SIGNATURE_SIZE);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t pub_key_len = 0;
	uint8_t pub_key[ED25519_PUBLIC_KEY_SIZE] = { 0 };

	const psa_key_id_t *psa_kid = kid;
	const psa_status_t ret = psa_export_key(
		*psa_kid, pub_key, ARRAY_SIZE(pub_key), &pub_key_len);

	if (PSA_SUCCESS != ret || ARRAY_SIZE(pub_key) != pub_key_len) {
		EDHOC_LOG_ERR("Export public key: %d, %zu", ret, pub_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const bool verified =
		compact_ed25519_verify(sign, pub_key, input, input_len);

	if (true != verified) {
		EDHOC_LOG_ERR("EdDSA verify");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_extract(void *user_ctx, const void *kid,
				 const uint8_t *salt, size_t salt_len,
				 uint8_t *prk, size_t prk_size, size_t *prk_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == salt || 0 == salt_len || NULL == prk ||
	    0 == prk_size || NULL == prk_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;

	const psa_key_id_t *psa_kid = kid;
	psa_key_derivation_operation_t ctx = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Get key attributes: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_setup(&ctx, psa_get_key_algorithm(&attr));
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Setup key derivation: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_input_bytes(
		&ctx, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Input salt: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_input_key(
		&ctx, PSA_KEY_DERIVATION_INPUT_SECRET, *psa_kid);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Input secret key: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_set_capacity(&ctx, prk_size);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Set capacity: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_output_bytes(&ctx, prk, prk_size);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Output bytes: %d", ret);
		goto psa_error;
	}

	*prk_len = prk_size;
	psa_key_derivation_abort(&ctx);

	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&ctx);
	EDHOC_LOG_ERR("HKDF extract: %d", ret);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_4_expand(void *user_ctx, const void *kid,
				const uint8_t *info, size_t info_len,
				uint8_t *okm, size_t okm_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == info || 0 == info_len || NULL == okm ||
	    0 == okm_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;

	const psa_key_id_t *psa_kid = kid;
	psa_key_derivation_operation_t ctx = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Get key attributes: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_setup(&ctx, psa_get_key_algorithm(&attr));
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Setup key derivation: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_input_key(
		&ctx, PSA_KEY_DERIVATION_INPUT_SECRET, *psa_kid);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Input secret key: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_input_bytes(
		&ctx, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Input info: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_set_capacity(&ctx, okm_len);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Set capacity: %d", ret);
		goto psa_error;
	}

	ret = psa_key_derivation_output_bytes(&ctx, okm, okm_len);
	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Output bytes: %d", ret);
		goto psa_error;
	}

	psa_key_derivation_abort(&ctx);
	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&ctx);
	EDHOC_LOG_ERR("HKDF expand: %d", ret);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_4_encrypt(void *user_ctx, const void *kid,
				 const uint8_t *nonce, size_t nonce_len,
				 const uint8_t *ad, size_t ad_len,
				 const uint8_t *ptxt, size_t ptxt_len,
				 uint8_t *ctxt, size_t ctxt_size,
				 size_t *ctxt_len)
{
	(void)user_ctx;

	/* Plaintext might be zero length buffer. */
	if (NULL == kid || NULL == nonce || 0 == nonce_len || NULL == ad ||
	    0 == ad_len || NULL == ctxt || 0 == ctxt_size || NULL == ctxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Get key attributes: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = psa_aead_encrypt(*psa_kid, psa_get_key_algorithm(&attr), nonce,
			       nonce_len, ad, ad_len, ptxt, ptxt_len, ctxt,
			       ctxt_size, ctxt_len);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("AEAD encryption: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_decrypt(void *user_ctx, const void *kid,
				 const uint8_t *nonce, size_t nonce_len,
				 const uint8_t *ad, size_t ad_len,
				 const uint8_t *ctxt, size_t ctxt_len,
				 uint8_t *ptxt, size_t ptxt_size,
				 size_t *ptxt_len)
{
	(void)user_ctx;

	/* Plaintext might be zero length buffer. */
	if (NULL == kid || NULL == nonce || 0 == nonce_len || NULL == ad ||
	    0 == ad_len || NULL == ctxt || 0 == ctxt_len || NULL == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Get key attributes: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = psa_aead_decrypt(*psa_kid, psa_get_key_algorithm(&attr), nonce,
			       nonce_len, ad, ad_len, ctxt, ctxt_len, ptxt,
			       ptxt_size, ptxt_len);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("AEAD decryption: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_4_hash(void *user_ctx, const uint8_t *input,
			      size_t input_len, uint8_t *hash, size_t hash_size,
			      size_t *hash_len)
{
	(void)user_ctx;

	if (NULL == input || 0 == input_len || NULL == hash || 0 == hash_size ||
	    NULL == hash_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_status_t ret = psa_hash_compute(
		PSA_ALG_SHA_256, input, input_len, hash, hash_size, hash_len);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("SHA256 hash: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

/* Module interface variables and constants -------------------------------- */

static const struct edhoc_keys edhoc_cipher_suite_4_keys = {
	.import_key = edhoc_cipher_suite_4_key_import,
	.destroy_key = edhoc_cipher_suite_4_key_destroy,
};

static const struct edhoc_crypto edhoc_cipher_suite_4_crypto = {
	.make_key_pair = edhoc_cipher_suite_4_make_key_pair,
	.key_agreement = edhoc_cipher_suite_4_key_agreement,
	.signature = edhoc_cipher_suite_4_signature,
	.verify = edhoc_cipher_suite_4_verify,
	.extract = edhoc_cipher_suite_4_extract,
	.expand = edhoc_cipher_suite_4_expand,
	.encrypt = edhoc_cipher_suite_4_encrypt,
	.decrypt = edhoc_cipher_suite_4_decrypt,
	.hash = edhoc_cipher_suite_4_hash,
};

static const struct edhoc_cipher_suite edhoc_cipher_suite_4_suite = {
	.value = EDHOC_CIPHER_SUITE_4_VALUE,
	.aead_key_length = EDHOC_CIPHER_SUITE_4_AEAD_KEY_LEN,
	.aead_tag_length = EDHOC_CIPHER_SUITE_4_AEAD_TAG_LEN,
	.aead_iv_length = EDHOC_CIPHER_SUITE_4_AEAD_IV_LEN,
	.hash_length = EDHOC_CIPHER_SUITE_4_HASH_LEN,
	.mac_length = EDHOC_CIPHER_SUITE_4_MAC_LEN,
	.ecc_key_length = EDHOC_CIPHER_SUITE_4_ECC_KEY_LEN,
	.ecc_sign_length = EDHOC_CIPHER_SUITE_4_ECC_SIGN_LEN,
};

const struct edhoc_keys *edhoc_cipher_suite_4_get_keys(void)
{
	return &edhoc_cipher_suite_4_keys;
}

const struct edhoc_crypto *edhoc_cipher_suite_4_get_crypto(void)
{
	return &edhoc_cipher_suite_4_crypto;
}

const struct edhoc_cipher_suite *edhoc_cipher_suite_4_get_suite(void)
{
	return &edhoc_cipher_suite_4_suite;
}
