/**
 * \file    cipher_suite_test_hash.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite hash tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_hash.h"
#include "cipher_suite_driver.h"

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

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
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_hash(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	void *operation = NULL;

	ret = crypto->hash_init(NULL, &operation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(operation);

	/* Absorb the input in two chunks when it is long enough, exercising the
	 * multipart path; a one-shot update covers short inputs. */
	const size_t first = suite->hash.input.length / 2U;

	if (0U != first) {
		ret = crypto->hash_update(NULL, operation,
					  suite->hash.input.pointer, first);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = crypto->hash_update(NULL, operation,
					  suite->hash.input.pointer + first,
					  suite->hash.input.length - first);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	} else {
		ret = crypto->hash_update(NULL, operation,
					  suite->hash.input.pointer,
					  suite->hash.input.length);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}

	uint8_t hash[params->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_length = 0;

	ret = crypto->hash_finish(NULL, operation, hash, ARRAY_SIZE(hash),
				  &hash_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(suite->hash.expected.length, hash_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(suite->hash.expected.pointer, hash,
				      suite->hash.expected.length);
}

void cipher_suite_test_hash_null_args(
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

	const uint8_t input[8] = { 0 };
	uint8_t hash[params->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_length = 0;

	/* Each entry point rejects a null operation slot or handle. */
	ret = crypto->hash_init(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_abort(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_update(NULL, NULL, input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_finish(NULL, NULL, hash, ARRAY_SIZE(hash),
				  &hash_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* On a live operation, hash_update rejects a null or empty input and
	 * hash_finish rejects null outputs; none release the slot, so abort it
	 * at the end. */
	void *operation = NULL;
	ret = crypto->hash_init(NULL, &operation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(operation);

	ret = crypto->hash_update(NULL, operation, NULL, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_update(NULL, operation, input, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_finish(NULL, operation, NULL, ARRAY_SIZE(hash),
				  &hash_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_finish(NULL, operation, hash, ARRAY_SIZE(hash),
				  NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->hash_abort(NULL, operation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_hash_small_buffer(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const uint8_t input[16] = { 0 };

	void *operation = NULL;

	ret = crypto->hash_init(NULL, &operation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(operation);

	ret = crypto->hash_update(NULL, operation, input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* A hash buffer smaller than the digest is rejected. */
	uint8_t hash[4] = { 0 };
	size_t hash_length = 0;

	ret = crypto->hash_finish(NULL, operation, hash, ARRAY_SIZE(hash),
				  &hash_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

void cipher_suite_test_hash_abort_frees_pool_slot(
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

	static const uint8_t input[] = "EDHOC hash abort input";

	/* Fill the whole operation pool. */
	size_t live = 0;
	void *operations[16] = { 0 };

	for (size_t i = 0; i < ARRAY_SIZE(operations); ++i) {
		if (EDHOC_SUCCESS != crypto->hash_init(NULL, &operations[i])) {
			break;
		}

		live += 1;
	}

	TEST_ASSERT_GREATER_THAN(0, live);

	/* With the pool full, a further init fails. */
	void *overflow = NULL;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE,
			  crypto->hash_init(NULL, &overflow));

	/* Aborting one operation must return its slot to the pool, so a fresh
	 * init succeeds again. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->hash_abort(NULL, operations[0]));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->hash_init(NULL, &operations[0]));

	/* The reused slot still produces a correct digest. */
	ret = crypto->hash_update(NULL, operations[0], input,
				  sizeof(input) - 1U);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t hash_length = 0;
	uint8_t hash[params->hash_length];
	memset(hash, 0, sizeof(hash));

	ret = crypto->hash_finish(NULL, operations[0], hash, ARRAY_SIZE(hash),
				  &hash_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->hash_length, hash_length);

	/* Release the remaining live operations. */
	for (size_t i = 1; i < live; ++i) {
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  crypto->hash_abort(NULL, operations[i]));
	}
}
