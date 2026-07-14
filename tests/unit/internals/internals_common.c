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
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */

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
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_crypto(ctx, internals_crypto));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_credentials(ctx, &test_cred_stubs));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_platform(ctx, test_get_platform()));
}

void internals_inject_prk(struct edhoc_context *ctx,
			  enum edhoc_key_slot_id slot, const uint8_t *prk,
			  size_t prk_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, prk, prk_len, &kid));

	memcpy(ctx->key_slots[slot].key_id, &kid, sizeof(kid));
	ctx->key_slots[slot].present = true;
}

void internals_inject_ecdh_key(uint8_t *key_id, const uint8_t *priv,
			       size_t priv_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, priv, priv_len, &kid));

	memcpy(key_id, &kid, sizeof(kid));
}
