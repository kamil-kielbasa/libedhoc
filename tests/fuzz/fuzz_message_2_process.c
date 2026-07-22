/**
 * \file    fuzz_message_2_process.c
 * \author  Kamil Kielbasa
 * \brief   libFuzzer harness for edhoc_message_2_process().
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
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	edhoc_bind_ead(&ctx, &test_ead_stubs);
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());

	edhoc_bind_credentials(&ctx, &test_cred_stubs);
	edhoc_bind_platform(&ctx, test_get_platform());

	/* Pre-seed context state as if message_1 was already composed. */
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.machine = EDHOC_SM_WAIT_M2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.negotiation.selected_cipher_suite_index = 0;
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, ctx.state.th.length);
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	/* Seed the initiator ephemeral private key as a live key-store handle;
	 * message_2 processing decapsulates G_XY with it. */
	uint8_t dummy_eph[32];
	memset(dummy_eph, 0xBB, sizeof(dummy_eph));

	psa_key_attributes_t eph_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&eph_attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&eph_attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&eph_attr, PSA_ALG_ECDH);
	psa_set_key_type(&eph_attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));

	psa_key_id_t eph_kid = PSA_KEY_ID_NULL;
	if (PSA_SUCCESS ==
	    psa_import_key(&eph_attr, dummy_eph, sizeof(dummy_eph), &eph_kid)) {
		memcpy(ctx.key_slots[EDHOC_KEY_SLOT_EPHEMERAL].key_id, &eph_kid,
		       sizeof(eph_kid));
		ctx.key_slots[EDHOC_KEY_SLOT_EPHEMERAL].present = true;
	}

	edhoc_message_2_process(&ctx, data, size);

	edhoc_context_deinit(&ctx);
	return 0;
}
