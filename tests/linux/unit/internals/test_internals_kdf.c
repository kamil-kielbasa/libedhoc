/**
 * \file    test_internals_kdf.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_kdf_internal.c.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_kdf);

TEST_SETUP(internals_kdf)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_kdf)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_kdf, extract_null_args)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t key_id[4] = { 0 };
	const uint8_t salt[8] = { 0 };

	int ret = edhoc_kdf_extract(NULL, key_id, salt, ARRAY_SIZE(salt),
				    EDHOC_KEY_SLOT_PRK_2E);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_extract(&ctx, NULL, salt, ARRAY_SIZE(salt),
				EDHOC_KEY_SLOT_PRK_2E);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_extract(&ctx, key_id, NULL, ARRAY_SIZE(salt),
				EDHOC_KEY_SLOT_PRK_2E);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_extract(&ctx, key_id, salt, 0, EDHOC_KEY_SLOT_PRK_2E);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_kdf, expand_null_args)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t key_id[4] = { 0 };
	const uint8_t context[8] = { 0 };
	uint8_t output_key_id[4] = { 0 };

	int ret = edhoc_kdf_expand(NULL, key_id, 0, context,
				   ARRAY_SIZE(context), EDHOC_KEY_USAGE_KDF,
				   output_key_id, ARRAY_SIZE(output_key_id));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand(&ctx, NULL, 0, context, ARRAY_SIZE(context),
			       EDHOC_KEY_USAGE_KDF, output_key_id,
			       ARRAY_SIZE(output_key_id));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand(&ctx, key_id, 0, NULL, ARRAY_SIZE(context),
			       EDHOC_KEY_USAGE_KDF, output_key_id,
			       ARRAY_SIZE(output_key_id));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand(&ctx, key_id, 0, context, ARRAY_SIZE(context),
			       EDHOC_KEY_USAGE_KDF, NULL,
			       ARRAY_SIZE(output_key_id));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand(&ctx, key_id, 0, context, ARRAY_SIZE(context),
			       EDHOC_KEY_USAGE_KDF, output_key_id, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_kdf, expand_raw_null_args)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t key_id[4] = { 0 };
	const uint8_t context[8] = { 0 };
	uint8_t output[16] = { 0 };

	int ret = edhoc_kdf_expand_raw(NULL, key_id, 0, context,
				       ARRAY_SIZE(context), output,
				       ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand_raw(&ctx, NULL, 0, context, ARRAY_SIZE(context),
				   output, ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand_raw(&ctx, key_id, 0, NULL, ARRAY_SIZE(context),
				   output, ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand_raw(&ctx, key_id, 0, context,
				   ARRAY_SIZE(context), NULL,
				   ARRAY_SIZE(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_kdf_expand_raw(&ctx, key_id, 0, context,
				   ARRAY_SIZE(context), output, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_kdf)
{
	RUN_TEST_CASE(internals_kdf, extract_null_args);
	RUN_TEST_CASE(internals_kdf, expand_null_args);
	RUN_TEST_CASE(internals_kdf, expand_raw_null_args);
}
