/**
 * \file    cipher_suite_test_kdf.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite key-derivation tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_kdf.h"
#include "cipher_suite_driver.h"

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_kdf(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t ikm_id = cipher_suite_import_kdf_key(
		suite, suite->kdf.ikm.pointer, suite->kdf.ikm.length);

	psa_key_id_t prk_id = PSA_KEY_ID_NULL;

	ret = crypto->extract(NULL, &ikm_id, suite->kdf.salt.pointer,
			      suite->kdf.salt.length, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, &ikm_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t computed_okm[suite->kdf.okm.length];
	memset(computed_okm, 0, sizeof(computed_okm));

	ret = crypto->expand_raw(NULL, &prk_id, suite->kdf.info.pointer,
				 suite->kdf.info.length, computed_okm,
				 ARRAY_SIZE(computed_okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(suite->kdf.okm.pointer, computed_okm,
				      suite->kdf.okm.length);
}

void cipher_suite_test_kmac256_kat(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* The EDHOC SHAKE256 KDF is KMAC256 keyed by its first argument. Both
	 * directions of the same NIST SP 800-185 vector must reproduce the
	 * output: extract keys on the salt (= K) and consumes the IKM (= X),
	 * expand keys on the PRK (= K) and consumes the info (= X). */
	psa_key_id_t ikm_id = cipher_suite_import_kdf_key(
		suite, suite->kdf.ikm.pointer, suite->kdf.ikm.length);
	psa_key_id_t prk_id = PSA_KEY_ID_NULL;

	ret = crypto->extract(NULL, &ikm_id, suite->kdf.salt.pointer,
			      suite->kdf.salt.length, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t prk[params->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_length = 0;

	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_export_key(prk_id, prk, ARRAY_SIZE(prk),
					 &prk_length));
	TEST_ASSERT_EQUAL(suite->kdf.okm.length, prk_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(suite->kdf.okm.pointer, prk,
				      suite->kdf.okm.length);

	ret = crypto->destroy_key(NULL, &ikm_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = crypto->destroy_key(NULL, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	psa_key_id_t expand_prk_id = cipher_suite_import_kdf_key(
		suite, suite->kdf.salt.pointer, suite->kdf.salt.length);

	uint8_t okm[params->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = crypto->expand_raw(NULL, &expand_prk_id, suite->kdf.info.pointer,
				 suite->kdf.info.length, okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(suite->kdf.okm.pointer, okm,
				      suite->kdf.okm.length);

	ret = crypto->destroy_key(NULL, &expand_prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_expand_handles(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	static const uint8_t prk_bytes[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	};
	static const uint8_t info[] = { 'e', 'x', 'p', 'a', 'n', 'd' };

	psa_key_id_t prk_id = cipher_suite_import_kdf_key(
		suite, prk_bytes, ARRAY_SIZE(prk_bytes));

	/* KDF usage: the derived key handle expands to exactly the same bytes
	 * that expand_raw produces over identical info. */
	psa_key_id_t kdf_id = PSA_KEY_ID_NULL;
	ret = crypto->expand(NULL, &prk_id, info, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_KDF, &kdf_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t okm_from_handle_length = 0;
	uint8_t okm_from_handle[params->hash_length];
	memset(okm_from_handle, 0, sizeof(okm_from_handle));

	uint8_t okm_from_raw[params->hash_length];
	memset(okm_from_raw, 0, sizeof(okm_from_raw));

	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_export_key(kdf_id, okm_from_handle,
					 ARRAY_SIZE(okm_from_handle),
					 &okm_from_handle_length));
	TEST_ASSERT_EQUAL(params->hash_length, okm_from_handle_length);

	ret = crypto->expand_raw(NULL, &prk_id, info, ARRAY_SIZE(info),
				 okm_from_raw, ARRAY_SIZE(okm_from_raw));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm_from_raw, okm_from_handle,
				      ARRAY_SIZE(okm_from_raw));

	/* AEAD usage: the derived key handle is a working AEAD key -- prove it
	 * by encrypting and decrypting through the suite. */
	psa_key_id_t aead_id = PSA_KEY_ID_NULL;
	ret = crypto->expand(NULL, &prk_id, info, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_AEAD, &aead_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t aad[4] = { 1, 2, 3, 4 };
	const uint8_t plaintext[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0x5a, sizeof(nonce));

	size_t ciphertext_length = 0;
	uint8_t ciphertext[ARRAY_SIZE(plaintext) + params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	size_t decrypted_length = 0;
	uint8_t decrypted[ARRAY_SIZE(plaintext)];
	memset(decrypted, 0, sizeof(decrypted));

	ret = crypto->aead_encrypt(NULL, &aead_id, nonce, ARRAY_SIZE(nonce),
				   aad, ARRAY_SIZE(aad), plaintext,
				   ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->aead_decrypt(NULL, &aead_id, nonce, ARRAY_SIZE(nonce),
				   aad, ARRAY_SIZE(aad), ciphertext,
				   ciphertext_length, decrypted,
				   ARRAY_SIZE(decrypted), &decrypted_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(plaintext), decrypted_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(plaintext, decrypted,
				      ARRAY_SIZE(plaintext));

	ret = crypto->destroy_key(NULL, &kdf_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = crypto->destroy_key(NULL, &aead_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = crypto->destroy_key(NULL, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_extract_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t ikm_id = PSA_KEY_ID_NULL;
	psa_key_id_t prk_id = PSA_KEY_ID_NULL;
	const uint8_t salt[16] = { 0 };

	ret = crypto->extract(NULL, NULL, salt, ARRAY_SIZE(salt), &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->extract(NULL, &ikm_id, NULL, ARRAY_SIZE(salt), &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->extract(NULL, &ikm_id, salt, 0, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->extract(NULL, &ikm_id, salt, ARRAY_SIZE(salt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_extract_wrong_key_type(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	const uint8_t salt[16] = { 0 };
	psa_key_id_t prk_id = PSA_KEY_ID_NULL;

	ret = crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt), &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_extract_destroyed_key(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t raw_key[params->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t key_id = cipher_suite_import_kdf_key(suite, raw_key,
							  ARRAY_SIZE(raw_key));

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[16] = { 0 };
	psa_key_id_t prk_id = PSA_KEY_ID_NULL;

	ret = crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt), &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_expand_derive_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t prk_id = PSA_KEY_ID_NULL;
	psa_key_id_t out_id = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };

	ret = crypto->expand(NULL, NULL, info, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_KDF, &out_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand(NULL, &prk_id, NULL, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_KDF, &out_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand(NULL, &prk_id, info, 0, EDHOC_KEY_USAGE_KDF,
			     &out_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand(NULL, &prk_id, info, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_KDF, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_expand_invalid_usage(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t prk_id = PSA_KEY_ID_NULL;
	psa_key_id_t out_id = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };

	/* The usage switch rejects unknown values before touching the key. */
	ret = crypto->expand(NULL, &prk_id, info, ARRAY_SIZE(info),
			     (enum edhoc_key_usage)99, &out_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_expand_derive_stale_prk(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* A destroyed PRK handle cannot be exported, so expand must fail. */
	const uint8_t prk_material[32] = { 1, 2, 3, 4 };
	const uint8_t info[8] = { 5, 6, 7, 8 };
	psa_key_id_t out_id = PSA_KEY_ID_NULL;

	psa_key_id_t prk_id = cipher_suite_import_kdf_key(
		suite, prk_material, ARRAY_SIZE(prk_material));

	ret = crypto->destroy_key(NULL, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->expand(NULL, &prk_id, info, ARRAY_SIZE(info),
			     EDHOC_KEY_USAGE_KDF, &out_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_expand_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t okm[params->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = crypto->expand_raw(NULL, NULL, NULL, 0, okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_expand_raw_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t prk_id = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };
	uint8_t output[params->hash_length];
	memset(output, 0, sizeof(output));

	ret = crypto->expand_raw(NULL, NULL, info, ARRAY_SIZE(info), output,
				 ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand_raw(NULL, &prk_id, NULL, ARRAY_SIZE(info), output,
				 ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand_raw(NULL, &prk_id, info, 0, output,
				 ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand_raw(NULL, &prk_id, info, ARRAY_SIZE(info), NULL,
				 ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->expand_raw(NULL, &prk_id, info, ARRAY_SIZE(info), output,
				 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_expand_wrong_key_type(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	const uint8_t info[16] = { 0 };
	uint8_t okm[params->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = crypto->expand_raw(NULL, &key_id, info, ARRAY_SIZE(info), okm,
				 ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_expand_destroyed_key(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t raw_key[params->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t key_id = cipher_suite_import_kdf_key(suite, raw_key,
							  ARRAY_SIZE(raw_key));

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[params->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = crypto->expand_raw(NULL, &key_id, info, ARRAY_SIZE(info), okm,
				 ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_expand_output_too_large(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t raw_key[params->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t key_id = cipher_suite_import_kdf_key(suite, raw_key,
							  ARRAY_SIZE(raw_key));

	const uint8_t info[4] = { 0xab, 0xcd, 0xef, 0x01 };
	const size_t okm_length = 65536;
	uint8_t *okm = malloc(okm_length);
	TEST_ASSERT_NOT_NULL(okm);

	/* The KDF caps output at 255 * hash_length; a larger request fails. */
	ret = crypto->expand_raw(NULL, &key_id, info, ARRAY_SIZE(info), okm,
				 okm_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
	free(okm);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}
