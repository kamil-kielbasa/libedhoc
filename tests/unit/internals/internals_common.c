/**
 * \file    internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Shared fixtures for internals unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
#include "test_platform.h"
#include "test_credentials.h"
#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */

const struct edhoc_keys *internals_keys;
const struct edhoc_crypto *internals_crypto;

/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void internals_setup_crypto_context(struct edhoc_context *ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	memset(ctx, 0, sizeof(*ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_init(ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_set_methods(ctx, method, 1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_set_cipher_suites(
				  ctx, edhoc_cipher_suite_0_get_suite(), 1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_set_connection_id(ctx, &cid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_bind_keys(ctx, internals_keys));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_crypto(ctx, internals_crypto));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_credentials(ctx, &test_cred_stubs));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_platform(ctx, test_get_platform()));
}
