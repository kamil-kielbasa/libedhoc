/**
 * \file    fuzz_message_2_process.c
 * \brief   libFuzzer harness for edhoc_message_2_process().
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>
#include "edhoc_cipher_suite_0.h"

#include <psa/crypto.h>

#include "test_ead.h"
#include "test_credentials.h"
#include "test_cipher_suites.h"

static bool psa_initialized = false;

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

	edhoc_set_cipher_suites(&ctx, &test_cipher_suite_0, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	edhoc_bind_ead(&ctx, &test_ead_stubs);
	edhoc_bind_keys(&ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());

	edhoc_bind_credentials(&ctx, &test_cred_stubs);

	/* Pre-seed context state as if message_1 was already composed. */
	ctx.role = EDHOC_INITIATOR;
	ctx.status = EDHOC_SM_WAIT_M2;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.chosen_csuite_idx = 0;
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, ctx.th_len);
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;
	ctx.dh_priv_key_len = 32;
	memset(ctx.dh_priv_key, 0xBB, ctx.dh_priv_key_len);

	edhoc_message_2_process(&ctx, data, size);

	edhoc_context_deinit(&ctx);
	return 0;
}
