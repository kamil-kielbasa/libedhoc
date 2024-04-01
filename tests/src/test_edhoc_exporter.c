/**
 * @file    test_edhoc_exporter.c
 * @author  Kamil Kielbasa
 * @brief   Unit test for EDHOC exporter.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_edhoc_exporter.h"
#include "edhoc.h"
#include "test_crypto.h"
#include "test_credentials.h"
#include "test_vectors_p256_v16.h"

/* standard library headers: */
#include <string.h>
#include <assert.h>

/* crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_cipher_suite cipher_suite_2 = {
	.value = 2,
	.aead_key_len = 16,
	.aead_tag_len = 8,
	.aead_iv_len = 13,
	.hash_len = 32,
	.mac_len = 32,
	.ecc_key_len = 32,
	.ecc_sign_len = 64,
};

static const struct edhoc_keys keys = {
	.generate_key = edhoc_keys_generate,
	.destroy_key = edhoc_keys_destroy,
};

static const struct edhoc_crypto crypto_mocked = {
	.make_key_pair = test_crypto_make_key_pair_resp_mocked_x509_chain,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign_resp_mocked_x509_chain,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = NULL,
	.decrypt = test_crypto_decrypt,
	.hash = test_crypto_hash,
};

static const struct edhoc_credentials cred = {
	.fetch = test_cred_fetch_resp_x509_chain,
	.verify = test_cred_verify_resp_mocked_x509_chain,
};

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void test_edhoc_exporter(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context ctx = { 0 };

	ret = edhoc_context_init(&ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&ctx, test_vector_1_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&ctx, &test_vector_1_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&ctx, crypto_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&ctx, cred);
	assert(EDHOC_SUCCESS == ret);

	/* Required injections: */
	ctx.status = COMPLETED;

	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.prk_len = ARRAY_SIZE(test_vector_1_prk_out);
	memcpy(ctx.prk, test_vector_1_prk_out, ctx.prk_len);

	uint8_t secret[ARRAY_SIZE(test_vector_1_oscore_secret_raw)] = { 0 };
	uint8_t salt[ARRAY_SIZE(test_vector_1_oscore_salt_raw)] = { 0 };

	ret = edhoc_export_secret_and_salt(&ctx, secret, ARRAY_SIZE(secret),
					   salt, ARRAY_SIZE(salt));

	assert(EDHOC_SUCCESS == ret);
	assert(0 == memcmp(secret, test_vector_1_oscore_secret_raw,
			   sizeof(test_vector_1_oscore_secret_raw)));
	assert(0 == memcmp(salt, test_vector_1_oscore_salt_raw,
			   sizeof(test_vector_1_oscore_salt_raw)));
}