/**
 * \file    fuzz_message_1_process.c
 * \brief   libFuzzer harness for edhoc_message_1_process().
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>
#include "edhoc_cipher_suite_0.h"

#include <psa/crypto.h>

static bool psa_initialized = false;

static int auth_cred_fetch_stub(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	(void)auth_cred;
	return EDHOC_SUCCESS;
}

static int auth_cred_verify_stub(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;
	static const uint8_t dummy_key[32] = { 0 };
	*pub_key = dummy_key;
	*pub_key_len = sizeof(dummy_key);
	return EDHOC_SUCCESS;
}

static int ead_compose_stub(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	*ead_token_len = 0;
	return EDHOC_SUCCESS;
}

static int ead_process_stub(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	return EDHOC_SUCCESS;
}

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

	const struct edhoc_cipher_suite csuite = {
		.value = 0,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	};
	edhoc_set_cipher_suites(&ctx, &csuite, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	const struct edhoc_ead ead = {
		.compose = ead_compose_stub,
		.process = ead_process_stub,
	};
	edhoc_bind_ead(&ctx, &ead);
	edhoc_bind_keys(&ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());

	const struct edhoc_credentials cred = {
		.fetch = auth_cred_fetch_stub,
		.verify = auth_cred_verify_stub,
	};
	edhoc_bind_credentials(&ctx, &cred);

	ctx.role = EDHOC_RESPONDER;
	ctx.status = EDHOC_SM_START;

	edhoc_message_1_process(&ctx, data, size);

	edhoc_context_deinit(&ctx);
	return 0;
}
