/**
 * \file    fuzz_message_1_process.c
 * \author  Kamil Kielbasa
 * \brief   libFuzzer harness feeding arbitrary input to
 *          edhoc_message_1_process().
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function definitions --------------------------------------------- */

static void platform_zeroize(void *buffer, size_t length)
{
	(void)memset(buffer, 0, length);
}

static int
auth_cred_select_local_stub(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
	selected->x509_chain.count = 1;
	static const uint8_t dummy_cert[] = { 0x30, 0x00 };
	selected->x509_chain.certificate[0].value = dummy_cert;
	selected->x509_chain.certificate[0].length = ARRAY_SIZE(dummy_cert);
	memset(selected->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

static int auth_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	static const uint8_t dummy_key[32] = { 0 };

	(void)user_ctx;
	(void)call_ctx;

	if (NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != received->label ||
	    0 == received->x509_chain.count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->credential = received->x509_chain.certificate[0];
	trusted->format = EDHOC_CREDENTIAL_FORMAT_RAW;
	trusted->public_key.value = dummy_key;
	trusted->public_key.length = ARRAY_SIZE(dummy_key);

	return EDHOC_SUCCESS;
}

static int ead_compose_stub(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)ead_token;
	(void)ead_token_size;

	*ead_token_len = 0;

	return EDHOC_SUCCESS;
}

static int ead_process_stub(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)ead_token;
	(void)ead_token_size;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Start from a clean PSA subsystem on every input and tear it down at
	 * the end, so imported key slots never accumulate across iterations. */
	(void)psa_crypto_init();

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	const struct edhoc_cipher_suite csuites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2),
	};
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	const struct edhoc_ead ead = {
		.compose = ead_compose_stub,
		.process = ead_process_stub,
	};
	const struct edhoc_credentials cred = {
		.select_local = auth_cred_select_local_stub,
		.authenticate_peer = auth_cred_authenticate_peer_stub,
	};
	const struct edhoc_platform platform = {
		.zeroize = platform_zeroize,
	};

	struct edhoc_context ctx = { 0 };

	/* Deterministic setup: return values are deliberately ignored — the
	 * harness only checks that arbitrary input never crashes. */
	(void)edhoc_context_init(&ctx);
	(void)edhoc_set_methods(&ctx, methods, ARRAY_SIZE(methods));
	(void)edhoc_set_cipher_suites(&ctx, csuites, ARRAY_SIZE(csuites));
	(void)edhoc_set_connection_id(&ctx, &cid);
	(void)edhoc_bind_ead(&ctx, &ead);
	(void)edhoc_bind_crypto(
		&ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	(void)edhoc_bind_credentials(&ctx, &cred);
	(void)edhoc_bind_platform(&ctx, &platform);

	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_START;

	/* Fuzz target. */
	(void)edhoc_message_1_process(&ctx, data, size);

	(void)edhoc_context_deinit(&ctx);

	mbedtls_psa_crypto_free();

	return 0;
}
