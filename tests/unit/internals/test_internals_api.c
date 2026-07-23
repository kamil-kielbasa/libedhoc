/**
 * \file    test_internals_api.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for remaining internal and public API edge cases.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_api);

TEST_SETUP(internals_api)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_api)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_api, cbor_tstr_oh_large)
{
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(200));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(300));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_tstr_oh(70000));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_tstr_oh((size_t)UINT32_MAX + 1));
}

TEST(internals_api, cbor_bstr_oh_large)
{
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(200));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(300));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_bstr_oh(70000));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_bstr_oh((size_t)UINT32_MAX + 1));
}

TEST(internals_api, cbor_array_oh_large)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(1));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(100));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_oh(1000));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_array_oh(70000));
}

TEST(internals_api, export_oscore_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_context_raw(NULL, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_export_oscore_context_raw(&ctx, NULL, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_api, export_oscore_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.machine = 0; /* Not completed */
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;
	ctx.is_oscore_export_allowed = true;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_api, key_update_null)
{
	struct edhoc_context ctx = { 0 };
	uint8_t entropy[16] = { 0 };

	int ret = edhoc_export_key_update(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_export_key_update(&ctx, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_api)
{
	RUN_TEST_CASE(internals_api, cbor_tstr_oh_large);
	RUN_TEST_CASE(internals_api, cbor_bstr_oh_large);
	RUN_TEST_CASE(internals_api, cbor_array_oh_large);
	RUN_TEST_CASE(internals_api, export_oscore_null);
	RUN_TEST_CASE(internals_api, export_oscore_bad_state);
	RUN_TEST_CASE(internals_api, key_update_null);
}
