/**
 * @file    test_edhoc_x509_hash.c
 * @author  Kamil Kielbasa
 * @brief   Unit test for EDHOC (authentication via X509 hash).
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_edhoc_x509_hash.h"
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

static const struct edhoc_crypto crypto_init_mocked = {
	.make_key_pair = test_crypto_make_key_pair_init_mocked_x509_hash,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign_init_mocked_x509_hash,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = test_crypto_encrypt,
	.decrypt = NULL,
	.hash = test_crypto_hash,
};

static const struct edhoc_crypto crypto_resp_mocked = {
	.make_key_pair = test_crypto_make_key_pair_resp_mocked_x509_hash,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign_resp_mocked_x509_hash,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = NULL,
	.decrypt = test_crypto_decrypt,
	.hash = test_crypto_hash,
};

static const struct edhoc_crypto crypto = {
	.make_key_pair = test_crypto_make_key_pair,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = test_crypto_encrypt,
	.decrypt = test_crypto_decrypt,
	.hash = test_crypto_hash,
};

static const struct edhoc_credentials cred_init_mocked = {
	.fetch = test_cred_fetch_init_x509_hash,
	.verify = test_cred_verify_init_mocked_x509_hash,
};

static const struct edhoc_credentials cred_resp_mocked = {
	.fetch = test_cred_fetch_resp_x509_hash,
	.verify = test_cred_verify_resp_mocked_x509_hash,
};

static const struct edhoc_credentials cred_init = {
	.fetch = test_cred_fetch_init_x509_hash,
	.verify = test_cred_verify_init_x509_hash,
};

static const struct edhoc_credentials cred_resp = {
	.fetch = test_cred_fetch_resp_x509_hash,
	.verify = test_cred_verify_resp_x509_hash,
};

/* Static function declarations -------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length)
{
	printf("%s:\tLEN( %zu )\n", name, array_length);

	for (size_t i = 0; i < array_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", array[i]);
	}

	printf("\n\n");
}

/* Module interface function definitions ----------------------------------- */

void test_edhoc_x509_hash_message_1_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context init_ctx = { 0 };

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_2_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief EDHOC message 1 compose.
         */
	size_t msg_1_len = 0;
	uint8_t msg_1[ARRAY_SIZE(test_vector_2_message_1)] = { 0 };
	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M2 == init_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_1) == msg_1_len);
	assert(0 == memcmp(test_vector_2_message_1, msg_1, msg_1_len));

	assert(EDHOC_PRK_STATE_INVALID == init_ctx.prk_state);
	assert(0 == init_ctx.prk_len);

	assert(EDHOC_TH_STATE_1 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_h_message_1_raw) == init_ctx.th_len);
	assert(0 == memcmp(test_vector_2_h_message_1_raw, init_ctx.th,
			   init_ctx.th_len));

	assert(ARRAY_SIZE(test_vector_2_x_raw) == init_ctx.dh_priv_key_len);
	assert(0 == memcmp(test_vector_2_x_raw, init_ctx.dh_priv_key,
			   init_ctx.dh_priv_key_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_message_1_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context resp_ctx = { 0 };

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_2_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, test_vector_2_message_1,
				      ARRAY_SIZE(test_vector_2_message_1));
	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M1 == resp_ctx.status);

	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_h_message_1_raw) == resp_ctx.th_len);
	assert(0 == memcmp(test_vector_2_h_message_1_raw, resp_ctx.th,
			   resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);
	assert(0 == resp_ctx.prk_len);

	assert(1 == resp_ctx.peer_cid_len);
	assert((int8_t)resp_ctx.peer_cid[0] == (int8_t)test_vector_2_c_i_raw);

	assert(ARRAY_SIZE(test_vector_2_g_x_raw) ==
	       resp_ctx.dh_peer_pub_key_len);
	assert(0 == memcmp(test_vector_2_g_x_raw, resp_ctx.dh_peer_pub_key,
			   resp_ctx.dh_peer_pub_key_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_message_2_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context resp_ctx = { 0 };

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_2_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	resp_ctx.th_state = EDHOC_TH_STATE_1;
	resp_ctx.th_len = ARRAY_SIZE(test_vector_2_h_message_1_raw);
	memcpy(resp_ctx.th, test_vector_2_h_message_1_raw,
	       sizeof(test_vector_2_h_message_1_raw));

	resp_ctx.peer_cid[0] = (int8_t)test_vector_2_c_i_raw;
	resp_ctx.peer_cid_len = 1;

	resp_ctx.dh_peer_pub_key_len = ARRAY_SIZE(test_vector_2_g_x_raw);
	memcpy(resp_ctx.dh_peer_pub_key, test_vector_2_g_x_raw,
	       sizeof(resp_ctx.dh_peer_pub_key));

	resp_ctx.status = VERIFIED_M1;

	/**
         * \brief EDHOC message 2 compose.
         */
	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(test_vector_2_message_2)] = { 0 };
	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);
	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M3 == resp_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_2) == msg_2_len);
	assert(0 == memcmp(msg_2, test_vector_2_message_2, msg_2_len));

	assert(ARRAY_SIZE(test_vector_2_g_xy_raw) == resp_ctx.dh_secret_len);
	assert(0 == memcmp(resp_ctx.dh_secret, test_vector_2_g_xy_raw,
			   sizeof(resp_ctx.dh_secret)));

	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_3_raw) == resp_ctx.th_len);
	assert(0 ==
	       memcmp(resp_ctx.th, test_vector_2_th_3_raw, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_3e2m_raw) == resp_ctx.prk_len);
	assert(0 == memcmp(test_vector_2_prk_3e2m_raw, resp_ctx.prk,
			   resp_ctx.prk_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_message_2_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context init_ctx = { 0 };

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_2_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = WAIT_M2;

	init_ctx.dh_priv_key_len = ARRAY_SIZE(test_vector_2_x_raw);
	memcpy(init_ctx.dh_priv_key, test_vector_2_x_raw,
	       init_ctx.dh_priv_key_len);

	init_ctx.th_state = EDHOC_TH_STATE_1;
	init_ctx.th_len = ARRAY_SIZE(test_vector_2_h_message_1_raw);
	memcpy(init_ctx.th, test_vector_2_h_message_1_raw, init_ctx.th_len);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, test_vector_2_message_2,
				      ARRAY_SIZE(test_vector_2_message_2));

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M2 == init_ctx.status);

	assert(1 == init_ctx.peer_cid_len);
	assert(0 == memcmp(init_ctx.peer_cid, &test_vector_2_c_r_raw,
			   init_ctx.peer_cid_len));

	assert(ARRAY_SIZE(test_vector_2_g_xy_raw) == init_ctx.dh_secret_len);
	assert(0 == memcmp(init_ctx.dh_secret, test_vector_2_g_xy_raw,
			   sizeof(init_ctx.dh_secret)));

	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_3_raw) == init_ctx.th_len);
	assert(0 ==
	       memcmp(init_ctx.th, test_vector_2_th_3_raw, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_3e2m_raw) == init_ctx.prk_len);
	assert(0 == memcmp(test_vector_2_prk_3e2m_raw, init_ctx.prk,
			   init_ctx.prk_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_message_3_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context init_ctx = { 0 };

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_2_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = VERIFIED_M2;

	init_ctx.dh_secret_len = ARRAY_SIZE(test_vector_2_g_xy_raw);
	memcpy(init_ctx.dh_secret, test_vector_2_g_xy_raw,
	       sizeof(init_ctx.dh_secret));

	init_ctx.th_state = EDHOC_TH_STATE_3;
	init_ctx.th_len = ARRAY_SIZE(test_vector_2_th_3_raw);
	memcpy(init_ctx.th, test_vector_2_th_3_raw, init_ctx.th_len);

	init_ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	init_ctx.prk_len = ARRAY_SIZE(test_vector_2_prk_3e2m_raw);
	memcpy(init_ctx.prk, test_vector_2_prk_3e2m_raw, init_ctx.prk_len);

	/**
         * \brief EDHOC message 3 compose.
         */
	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(test_vector_2_message_3)] = { 0 };
	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == init_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_3) == msg_3_len);
	assert(0 == memcmp(msg_3, test_vector_2_message_3, msg_3_len));

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_4_raw) == init_ctx.th_len);
	assert(0 ==
	       memcmp(init_ctx.th, test_vector_2_th_4_raw, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_out) == init_ctx.prk_len);
	assert(0 ==
	       memcmp(init_ctx.prk, test_vector_2_prk_out, init_ctx.prk_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_message_3_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context resp_ctx = { 0 };

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_2_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	resp_ctx.status = WAIT_M3;

	resp_ctx.dh_secret_len = ARRAY_SIZE(test_vector_2_g_xy_raw);
	memcpy(resp_ctx.dh_secret, test_vector_2_g_xy_raw,
	       resp_ctx.dh_secret_len);

	resp_ctx.th_state = EDHOC_TH_STATE_3;
	resp_ctx.th_len = ARRAY_SIZE(test_vector_2_th_3_raw);
	memcpy(resp_ctx.th, test_vector_2_th_3_raw, resp_ctx.th_len);

	resp_ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	resp_ctx.prk_len = ARRAY_SIZE(test_vector_2_prk_3e2m_raw);
	memcpy(resp_ctx.prk, test_vector_2_prk_3e2m_raw, resp_ctx.prk_len);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, test_vector_2_message_3,
				      ARRAY_SIZE(test_vector_2_message_3));

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == resp_ctx.status);

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_4_raw) == resp_ctx.th_len);
	assert(0 ==
	       memcmp(resp_ctx.th, test_vector_2_th_4_raw, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_out) == resp_ctx.prk_len);
	assert(0 ==
	       memcmp(resp_ctx.prk, test_vector_2_prk_out, resp_ctx.prk_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_edhoc_e2e(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_2_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init_mocked);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_2_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp_mocked);
	assert(EDHOC_SUCCESS == ret);

	uint8_t buffer[400] = { 0 };

	/**
         * \brief EDHOC message 1 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;
	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M2 == init_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_1) == msg_1_len);
	assert(0 == memcmp(test_vector_2_message_1, msg_1, msg_1_len));

	assert(EDHOC_PRK_STATE_INVALID == init_ctx.prk_state);
	assert(0 == init_ctx.prk_len);

	assert(EDHOC_TH_STATE_1 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_h_message_1_raw) == init_ctx.th_len);
	assert(0 == memcmp(test_vector_2_h_message_1_raw, init_ctx.th,
			   init_ctx.th_len));

	assert(ARRAY_SIZE(test_vector_2_x_raw) == init_ctx.dh_priv_key_len);
	assert(0 == memcmp(test_vector_2_x_raw, init_ctx.dh_priv_key,
			   init_ctx.dh_priv_key_len));

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M1 == resp_ctx.status);

	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_h_message_1_raw) == resp_ctx.th_len);
	assert(0 == memcmp(test_vector_2_h_message_1_raw, resp_ctx.th,
			   resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);
	assert(0 == resp_ctx.prk_len);

	assert(1 == resp_ctx.peer_cid_len);
	assert((int8_t)resp_ctx.peer_cid[0] == (int8_t)test_vector_2_c_i_raw);

	assert(ARRAY_SIZE(test_vector_2_g_x_raw) ==
	       resp_ctx.dh_peer_pub_key_len);
	assert(0 == memcmp(test_vector_2_g_x_raw, resp_ctx.dh_peer_pub_key,
			   resp_ctx.dh_peer_pub_key_len));

	/**
         * \brief EDHOC message 2 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;
	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M3 == resp_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_2) == msg_2_len);
	assert(0 == memcmp(msg_2, test_vector_2_message_2, msg_2_len));

	assert(ARRAY_SIZE(test_vector_2_g_xy_raw) == resp_ctx.dh_secret_len);
	assert(0 == memcmp(resp_ctx.dh_secret, test_vector_2_g_xy_raw,
			   sizeof(resp_ctx.dh_secret)));

	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_3_raw) == resp_ctx.th_len);
	assert(0 ==
	       memcmp(resp_ctx.th, test_vector_2_th_3_raw, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_3e2m_raw) == resp_ctx.prk_len);
	assert(0 == memcmp(test_vector_2_prk_3e2m_raw, resp_ctx.prk,
			   resp_ctx.prk_len));

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M2 == init_ctx.status);

	assert(1 == init_ctx.peer_cid_len);
	assert(0 == memcmp(init_ctx.peer_cid, &test_vector_2_c_r_raw,
			   init_ctx.peer_cid_len));

	assert(ARRAY_SIZE(test_vector_2_g_xy_raw) == init_ctx.dh_secret_len);
	assert(0 == memcmp(init_ctx.dh_secret, test_vector_2_g_xy_raw,
			   sizeof(init_ctx.dh_secret)));

	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_3_raw) == init_ctx.th_len);
	assert(0 ==
	       memcmp(init_ctx.th, test_vector_2_th_3_raw, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_3e2m_raw) == init_ctx.prk_len);
	assert(0 == memcmp(test_vector_2_prk_3e2m_raw, init_ctx.prk,
			   init_ctx.prk_len));

	/**
         * \brief EDHOC message 3 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;
	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == init_ctx.status);

	assert(ARRAY_SIZE(test_vector_2_message_3) == msg_3_len);
	assert(0 == memcmp(msg_3, test_vector_2_message_3, msg_3_len));

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_4_raw) == init_ctx.th_len);
	assert(0 ==
	       memcmp(init_ctx.th, test_vector_2_th_4_raw, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_out) == init_ctx.prk_len);
	assert(0 ==
	       memcmp(init_ctx.prk, test_vector_2_prk_out, init_ctx.prk_len));

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == resp_ctx.status);

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(test_vector_2_th_4_raw) == resp_ctx.th_len);
	assert(0 ==
	       memcmp(resp_ctx.th, test_vector_2_th_4_raw, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);
	assert(ARRAY_SIZE(test_vector_2_prk_out) == resp_ctx.prk_len);
	assert(0 ==
	       memcmp(resp_ctx.prk, test_vector_2_prk_out, resp_ctx.prk_len));

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_secret[ARRAY_SIZE(test_vector_2_oscore_secret_raw)] = { 0 };
	uint8_t init_salt[ARRAY_SIZE(test_vector_2_oscore_salt_raw)] = { 0 };

	ret = edhoc_export_secret_and_salt(&init_ctx, init_secret,
					   ARRAY_SIZE(init_secret), init_salt,
					   ARRAY_SIZE(init_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_secret[ARRAY_SIZE(test_vector_2_oscore_secret_raw)] = { 0 };
	uint8_t resp_salt[ARRAY_SIZE(test_vector_2_oscore_salt_raw)] = { 0 };

	ret = edhoc_export_secret_and_salt(&resp_ctx, resp_secret,
					   ARRAY_SIZE(resp_secret), resp_salt,
					   ARRAY_SIZE(resp_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Verify both sides OSCORE secret & salt.
         */
	assert(0 == memcmp(init_secret, resp_secret,
			   sizeof(test_vector_2_oscore_secret_raw)));
	assert(0 == memcmp(test_vector_2_oscore_secret_raw, init_secret,
			   sizeof(test_vector_2_oscore_secret_raw)));
	assert(0 == memcmp(test_vector_2_oscore_secret_raw, resp_secret,
			   sizeof(test_vector_2_oscore_secret_raw)));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_x509_hash_edhoc_e2e_real_crypto(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_2_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_2_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_2_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp);
	assert(EDHOC_SUCCESS == ret);

	uint8_t buffer[400] = { 0 };

	/**
         * \brief EDHOC message 1 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;
	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M1 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;
	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M3 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 3 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;
	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == init_ctx.status);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == resp_ctx.status);

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_secret[16] = { 0 };
	uint8_t init_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&init_ctx, init_secret,
					   ARRAY_SIZE(init_secret), init_salt,
					   ARRAY_SIZE(init_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_secret[16] = { 0 };
	uint8_t resp_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&resp_ctx, resp_secret,
					   ARRAY_SIZE(resp_secret), resp_salt,
					   ARRAY_SIZE(resp_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Verify both sides OSCORE secret & salt.
         */
	assert(ARRAY_SIZE(init_secret) == ARRAY_SIZE(resp_secret));
	assert(0 == memcmp(init_secret, resp_secret, ARRAY_SIZE(init_secret)));

	assert(ARRAY_SIZE(init_salt) == ARRAY_SIZE(resp_salt));
	assert(0 == memcmp(init_salt, resp_salt, ARRAY_SIZE(init_salt)));

	print_array("Initiator - OSCORE master secret", init_secret,
		    ARRAY_SIZE(init_secret));

	print_array("Initiator - OSCORE master salt", init_salt,
		    ARRAY_SIZE(init_salt));

	print_array("Responder - OSCORE master secret", resp_secret,
		    ARRAY_SIZE(resp_secret));

	print_array("Responder - OSCORE master salt", resp_salt,
		    ARRAY_SIZE(resp_salt));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}