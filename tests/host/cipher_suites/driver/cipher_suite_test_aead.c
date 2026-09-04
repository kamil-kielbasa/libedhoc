/**
 * \file    cipher_suite_test_aead.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite AEAD tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_aead.h"
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
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** \brief Fill \p buffer with a deterministic byte ramp (0, 1, 2, ...). */
static void cipher_suite_fill_ramp(uint8_t *buffer, size_t length);

/* Static function definitions --------------------------------------------- */

static void cipher_suite_fill_ramp(uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; ++i) {
		buffer[i] = (uint8_t)i;
	}
}

/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_aead(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key[params->aead_key_length];
	cipher_suite_fill_ramp(key, sizeof(key));

	uint8_t iv[params->aead_iv_length];
	cipher_suite_fill_ramp(iv, sizeof(iv));

	const uint8_t associated_data[4] = { 0, 1, 2, 3 };
	const uint8_t plaintext[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	psa_key_id_t key_id =
		cipher_suite_import_aead_key(suite, key, ARRAY_SIZE(key));

	size_t ciphertext_length = 0;
	uint8_t ciphertext[ARRAY_SIZE(plaintext) + params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->aead_encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ciphertext), ciphertext_length);

	uint8_t decrypted[ARRAY_SIZE(plaintext)] = { 0 };
	size_t decrypted_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ciphertext_length, decrypted,
				   ARRAY_SIZE(decrypted), &decrypted_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(plaintext), decrypted_length);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(plaintext, decrypted,
				      ARRAY_SIZE(plaintext));
}

void cipher_suite_test_aead_empty_plaintext(
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

	uint8_t key[params->aead_key_length];
	cipher_suite_fill_ramp(key, sizeof(key));

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[4] = { 0x10, 0x11, 0x12, 0x13 };

	psa_key_id_t key_id =
		cipher_suite_import_aead_key(suite, key, ARRAY_SIZE(key));

	size_t ciphertext_length = 0;
	uint8_t ciphertext[params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   NULL, (size_t)0, ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->aead_tag_length, ciphertext_length);

	size_t plaintext_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ciphertext_length, NULL,
				   (size_t)0, &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)0, plaintext_length);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_aead_tag_tamper(
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

	uint8_t key[params->aead_key_length];
	cipher_suite_fill_ramp(key, sizeof(key));

	uint8_t iv[params->aead_iv_length];
	cipher_suite_fill_ramp(iv, sizeof(iv));

	const uint8_t associated_data[5] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	const uint8_t plaintext[16] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	};

	psa_key_id_t key_id =
		cipher_suite_import_aead_key(suite, key, ARRAY_SIZE(key));

	size_t ciphertext_length = 0;
	uint8_t ciphertext[ARRAY_SIZE(plaintext) + params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->aead_encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ciphertext), ciphertext_length);

	/* Flip the last byte: that lands inside the authentication tag. */
	ciphertext[ciphertext_length - 1U] ^= (uint8_t)0x80;

	uint8_t decrypted[ARRAY_SIZE(plaintext)] = { 0 };
	size_t decrypted_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ciphertext_length, decrypted,
				   ARRAY_SIZE(decrypted), &decrypted_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_aead_aad_tamper(
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

	uint8_t key[params->aead_key_length];
	cipher_suite_fill_ramp(key, sizeof(key));

	uint8_t iv[params->aead_iv_length];
	cipher_suite_fill_ramp(iv, sizeof(iv));

	const uint8_t associated_data_encrypt[4] = { 0x01, 0x02, 0x03, 0x04 };
	const uint8_t associated_data_decrypt[4] = { 0x01, 0x02, 0x03, 0x05 };
	const uint8_t plaintext[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	psa_key_id_t key_id =
		cipher_suite_import_aead_key(suite, key, ARRAY_SIZE(key));

	uint8_t ciphertext[ARRAY_SIZE(plaintext) + params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_length = 0;

	ret = crypto->aead_encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data_encrypt,
				   ARRAY_SIZE(associated_data_encrypt),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t decrypted[ARRAY_SIZE(plaintext)] = { 0 };
	size_t decrypted_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv),
				   associated_data_decrypt,
				   ARRAY_SIZE(associated_data_decrypt),
				   ciphertext, ciphertext_length, decrypted,
				   ARRAY_SIZE(decrypted), &decrypted_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_encrypt_null_args(
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

	/* A working key so each case fails only on the argument under test. */
	uint8_t key_bytes[params->aead_key_length];
	memset(key_bytes, 0x2b, sizeof(key_bytes));
	psa_key_id_t key_id = cipher_suite_import_aead_key(
		suite, key_bytes, ARRAY_SIZE(key_bytes));

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[4] = { 0 };
	const uint8_t plaintext[8] = { 0 };

	size_t ciphertext_length = 0;
	uint8_t ciphertext[ARRAY_SIZE(plaintext) + params->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->aead_encrypt(NULL, NULL, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_encrypt(NULL, &key_id, NULL, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   NULL, ARRAY_SIZE(associated_data), plaintext,
				   ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), NULL,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_encrypt_wrong_key_type(
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

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[16] = { 0 };
	const uint8_t plaintext[16] = { 0 };
	uint8_t ciphertext[32] = { 0 };
	size_t ciphertext_length = 0;

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_encrypt_destroyed_key(
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

	uint8_t raw_key[params->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t key_id = cipher_suite_import_aead_key(suite, raw_key,
							   ARRAY_SIZE(raw_key));

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[16] = { 0 };
	const uint8_t plaintext[16] = { 0 };
	uint8_t ciphertext[32] = { 0 };
	size_t ciphertext_length = 0;

	ret = crypto->aead_encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   plaintext, ARRAY_SIZE(plaintext), ciphertext,
				   ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_decrypt_null_args(
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

	/* A working key so each case fails only on the argument under test. */
	uint8_t key_bytes[params->aead_key_length];
	memset(key_bytes, 0x2b, sizeof(key_bytes));
	psa_key_id_t key_id = cipher_suite_import_aead_key(
		suite, key_bytes, ARRAY_SIZE(key_bytes));

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[4] = { 0 };
	const uint8_t ciphertext[24] = { 0 };

	uint8_t plaintext[8] = { 0 };
	size_t plaintext_length = 0;

	ret = crypto->aead_decrypt(NULL, NULL, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ARRAY_SIZE(ciphertext),
				   plaintext, ARRAY_SIZE(plaintext),
				   &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_decrypt(NULL, &key_id, NULL, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ARRAY_SIZE(ciphertext),
				   plaintext, ARRAY_SIZE(plaintext),
				   &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   NULL, ARRAY_SIZE(ciphertext), plaintext,
				   ARRAY_SIZE(plaintext), &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->aead_decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ARRAY_SIZE(ciphertext),
				   plaintext, ARRAY_SIZE(plaintext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_decrypt_wrong_key_type(
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

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[16] = { 0 };
	const uint8_t ciphertext[32] = { 0 };
	uint8_t plaintext[32] = { 0 };
	size_t plaintext_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ARRAY_SIZE(ciphertext),
				   plaintext, ARRAY_SIZE(plaintext),
				   &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_decrypt_destroyed_key(
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

	uint8_t raw_key[params->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t key_id = cipher_suite_import_aead_key(suite, raw_key,
							   ARRAY_SIZE(raw_key));

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[params->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t associated_data[16] = { 0 };
	const uint8_t ciphertext[32] = { 0 };
	uint8_t plaintext[32] = { 0 };
	size_t plaintext_length = 0;

	ret = crypto->aead_decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				   associated_data, ARRAY_SIZE(associated_data),
				   ciphertext, ARRAY_SIZE(ciphertext),
				   plaintext, ARRAY_SIZE(plaintext),
				   &plaintext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}
