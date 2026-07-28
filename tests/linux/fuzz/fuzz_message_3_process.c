/**
 * \file    fuzz_message_3_process.c
 * \author  Kamil Kielbasa
 * \brief   libFuzzer harness feeding arbitrary input to
 *          edhoc_message_3_process().
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
#include <stdbool.h>

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

static int auth_cred_fetch_stub(void *user_ctx,
				struct edhoc_auth_credentials *auth_cred)
{
	static const uint8_t dummy_cert[] = { 0x30, 0x00 };

	(void)user_ctx;

	if (NULL == auth_cred) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.certificate_count = 1;
	auth_cred->x509_chain.certificate[0] = dummy_cert;
	auth_cred->x509_chain.certificate_length[0] = sizeof(dummy_cert);
	memset(auth_cred->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_stub(void *user_ctx,
				 struct edhoc_auth_credentials *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	static const uint8_t dummy_key[32] = { 0 };

	(void)user_ctx;
	(void)auth_cred;

	if (NULL == pub_key || NULL == pub_key_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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
		.fetch = auth_cred_fetch_stub,
		.verify = auth_cred_verify_stub,
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

	/* Pre-seed context state as if message_2 was processed. */
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
	uint8_t dummy_prk[32] = { 0 };
	memset(dummy_prk, 0xCC, sizeof(dummy_prk));

	psa_key_attributes_t prk_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&prk_attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&prk_attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&prk_attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&prk_attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&prk_attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&prk_attr, dummy_prk,
						   sizeof(dummy_prk), &prk_kid);
	if (PSA_SUCCESS == status) {
		memcpy(ctx.key_slots[EDHOC_KEY_SLOT_PRK_3E2M].key_id, &prk_kid,
		       sizeof(prk_kid));
		ctx.key_slots[EDHOC_KEY_SLOT_PRK_3E2M].present = true;
	}

	/* Fuzz target. */
	(void)edhoc_message_3_process(&ctx, data, size);

	(void)edhoc_context_deinit(&ctx);

	mbedtls_psa_crypto_free();

	return 0;
}
