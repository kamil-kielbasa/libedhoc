/**
 * \file    fuzz_message_3_process.c
 * \author  Kamil Kielbasa
 * \brief   libFuzzer harness for edhoc_message_3_process().
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include "test_platform.h"
#include "edhoc_context_internal.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* EDHOC header: */
#include <edhoc/edhoc.h>

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Test helpers headers: */
#include "test_ead.h"
#include "test_credentials.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */
/* Static variables and constants ------------------------------------------ */

static bool psa_initialized = false;

/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!psa_initialized) {
		psa_crypto_init();
		psa_initialized = true;
	}

	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);

	if (EDHOC_SUCCESS != ret)
		return 0;

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&ctx, methods, 1);

	edhoc_set_cipher_suites(&ctx, edhoc_cipher_suite_0_get_suite(), 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	edhoc_bind_ead(&ctx, &test_ead_stubs);
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());

	edhoc_bind_credentials(&ctx, &test_cred_stubs);
	edhoc_bind_platform(&ctx, test_get_platform());

	/* Pre-seed context state as if message_2 was already composed. */
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_WAIT_M3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.negotiation.selected_cipher_suite_index = 0;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, ctx.state.th.length);
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	/* Seed PRK_3e2m as a live derive key-store handle; message_3 processing
	 * decrypts CIPHERTEXT_3 with a key expanded from it. */
	uint8_t dummy_prk[32];
	memset(dummy_prk, 0xCC, sizeof(dummy_prk));

	psa_key_attributes_t prk_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&prk_attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&prk_attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&prk_attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&prk_attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&prk_attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	if (PSA_SUCCESS ==
	    psa_import_key(&prk_attr, dummy_prk, sizeof(dummy_prk), &prk_kid)) {
		memcpy(ctx.key_slots[EDHOC_KEY_SLOT_PRK_3E2M].key_id, &prk_kid,
		       sizeof(prk_kid));
		ctx.key_slots[EDHOC_KEY_SLOT_PRK_3E2M].present = true;
	}

	edhoc_message_3_process(&ctx, data, size);

	edhoc_context_deinit(&ctx);
	return 0;
}
