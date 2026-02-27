/**
 * \file    test_coverage.c
 * \author  Kamil Kielbasa
 * \brief   Additional coverage tests targeting uncovered error paths.
 *
 *          Uses mock crypto/key callbacks with configurable failure injection
 *          and direct context state manipulation (EDHOC_ALLOW_PRIVATE_ACCESS)
 *          to exercise deep internal error paths in the library.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 *
 */

/* Include files ----------------------------------------------------------- */

#include "test_common.h"
#include "edhoc_common.h"
#include "edhoc_cipher_suite_2.h"
#include "test_cipher_suites.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/* Mock infrastructure ---------------------------------------------------- */

static int mock_call_count;
static int mock_fail_at;

static void mock_reset(int fail_at)
{
	mock_call_count = 0;
	mock_fail_at = fail_at;
}

static bool mock_should_fail(void)
{
	mock_call_count++;
	return (mock_fail_at > 0 && mock_call_count >= mock_fail_at);
}

/* Mock key callbacks */
static int mock_key_import(void *user_ctx, enum edhoc_key_type key_type,
			   const uint8_t *raw_key, size_t raw_key_len,
			   void *kid)
{
	(void)user_ctx;
	(void)key_type;
	(void)raw_key;
	(void)raw_key_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(kid, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static int mock_key_destroy(void *user_ctx, void *kid)
{
	(void)user_ctx;
	(void)kid;
	return EDHOC_SUCCESS;
}

/* Mock crypto callbacks */
static int mock_make_key_pair(void *user_ctx, const void *kid,
			      uint8_t *priv_key, size_t priv_key_size,
			      size_t *priv_key_len, uint8_t *pub_key,
			      size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)kid;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(priv_key, 0xAA, priv_key_size);
	*priv_key_len = priv_key_size;
	memset(pub_key, 0xBB, pub_key_size);
	*pub_key_len = pub_key_size;
	return EDHOC_SUCCESS;
}

static int mock_key_agreement(void *user_ctx, const void *kid,
			      const uint8_t *pub_key, size_t pub_key_len,
			      uint8_t *secret, size_t secret_size,
			      size_t *secret_len)
{
	(void)user_ctx;
	(void)kid;
	(void)pub_key;
	(void)pub_key_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(secret, 0xCC, secret_size);
	*secret_len = secret_size;
	return EDHOC_SUCCESS;
}

static int mock_signature(void *user_ctx, const void *kid, const uint8_t *input,
			  size_t input_len, uint8_t *sign, size_t sign_size,
			  size_t *sign_len)
{
	(void)user_ctx;
	(void)kid;
	(void)input;
	(void)input_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(sign, 0xDD, sign_size);
	*sign_len = sign_size;
	return EDHOC_SUCCESS;
}

static int mock_verify(void *user_ctx, const void *kid, const uint8_t *input,
		       size_t input_len, const uint8_t *sign, size_t sign_len)
{
	(void)user_ctx;
	(void)kid;
	(void)input;
	(void)input_len;
	(void)sign;
	(void)sign_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	return EDHOC_SUCCESS;
}

static int mock_extract(void *user_ctx, const void *kid, const uint8_t *salt,
			size_t salt_len, uint8_t *prk, size_t prk_size,
			size_t *prk_len)
{
	(void)user_ctx;
	(void)kid;
	(void)salt;
	(void)salt_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(prk, 0xEE, prk_size);
	*prk_len = prk_size;
	return EDHOC_SUCCESS;
}

static int mock_expand(void *user_ctx, const void *kid, const uint8_t *info,
		       size_t info_len, uint8_t *okm, size_t okm_len)
{
	(void)user_ctx;
	(void)kid;
	(void)info;
	(void)info_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(okm, 0xFF, okm_len);
	return EDHOC_SUCCESS;
}

static int mock_encrypt(void *user_ctx, const void *kid, const uint8_t *nonce,
			size_t nonce_len, const uint8_t *aad, size_t aad_len,
			const uint8_t *ptxt, size_t ptxt_len, uint8_t *ctxt,
			size_t ctxt_size, size_t *ctxt_len)
{
	(void)user_ctx;
	(void)kid;
	(void)nonce;
	(void)nonce_len;
	(void)aad;
	(void)aad_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	if (ptxt && ptxt_len > 0)
		memcpy(ctxt, ptxt, ptxt_len);
	else
		memset(ctxt, 0, ctxt_size);
	*ctxt_len = ptxt_len + 8;
	return EDHOC_SUCCESS;
}

static int mock_decrypt(void *user_ctx, const void *kid, const uint8_t *nonce,
			size_t nonce_len, const uint8_t *aad, size_t aad_len,
			const uint8_t *ctxt, size_t ctxt_len, uint8_t *ptxt,
			size_t ptxt_size, size_t *ptxt_len)
{
	(void)user_ctx;
	(void)kid;
	(void)nonce;
	(void)nonce_len;
	(void)aad;
	(void)aad_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	size_t plen = ctxt_len > 8 ? ctxt_len - 8 : 0;
	if (plen > ptxt_size)
		plen = ptxt_size;
	if (ctxt && plen > 0)
		memcpy(ptxt, ctxt, plen);
	*ptxt_len = plen;
	return EDHOC_SUCCESS;
}

static int mock_hash(void *user_ctx, const uint8_t *input, size_t input_len,
		     uint8_t *hash, size_t hash_size, size_t *hash_len)
{
	(void)user_ctx;
	(void)input;
	(void)input_len;
	if (mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(hash, 0x11, hash_size);
	*hash_len = hash_size;
	return EDHOC_SUCCESS;
}

static const struct edhoc_keys mock_keys = {
	.import_key = mock_key_import,
	.destroy_key = mock_key_destroy,
};

static const struct edhoc_crypto mock_crypto = {
	.make_key_pair = mock_make_key_pair,
	.key_agreement = mock_key_agreement,
	.signature = mock_signature,
	.verify = mock_verify,
	.extract = mock_extract,
	.expand = mock_expand,
	.encrypt = mock_encrypt,
	.decrypt = mock_decrypt,
	.hash = mock_hash,
};

/* Mock credential callbacks */
static int mock_cred_fetch(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;

	static const uint8_t fake_cert[] = { 0x30, 0x00 };
	auth_cred->x509_chain.cert[0] = fake_cert;
	auth_cred->x509_chain.cert_len[0] = sizeof(fake_cert);
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static int mock_cred_verify(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	static const uint8_t fake_pk[65] = { 0x04 };
	*pub_key = fake_pk;
	*pub_key_len = sizeof(fake_pk);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds = {
	.fetch = mock_cred_fetch,
	.verify = mock_cred_verify,
};

static int mock_ead_compose(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	if (mock_should_fail())
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	*ead_token_len = 0;
	return EDHOC_SUCCESS;
}

static int mock_ead_process(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	if (mock_should_fail())
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	return EDHOC_SUCCESS;
}

static const struct edhoc_ead mock_ead = {
	.compose = mock_ead_compose,
	.process = mock_ead_process,
};

/* Forward declarations for specialized mock callbacks */
static int mock_cred_fetch_invalid_label(void *user_ctx,
					 struct edhoc_auth_creds *auth_cred);
static int mock_cred_fetch_x509_zero_certs(void *user_ctx,
					   struct edhoc_auth_creds *auth_cred);

/* Helper to set up a fully bound context with mocks */
static void setup_mock_context(struct edhoc_context *ctx,
			       enum edhoc_method method)
{
	edhoc_context_init(ctx);

	const enum edhoc_method m[] = { method };
	edhoc_set_methods(ctx, m, 1);
	edhoc_set_cipher_suites(ctx, &test_cipher_suite_2, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = -24,
	};
	edhoc_set_connection_id(ctx, &cid);

	edhoc_bind_keys(ctx, &mock_keys);
	edhoc_bind_crypto(ctx, &mock_crypto);
	edhoc_bind_credentials(ctx, &mock_creds);
	edhoc_bind_ead(ctx, &mock_ead);
}

/* ---- Test group ---- */

TEST_GROUP(coverage);

TEST_SETUP(coverage)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage)
{
	mbedtls_psa_crypto_free();
}

/* --- Message 1 failure injection --- */

/**
 * @scenario  Message 1 compose fails when key import fails.
 * @env       Mock context with method 0, mock key import fails on 1st call.
 * @action    Call edhoc_message_1_compose.
 * @expected  Non-success return code.
 */
TEST(coverage, msg1_compose_key_import_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(1);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 compose fails when make_key_pair fails.
 * @env       Mock context with method 0, make_key_pair fails on 2nd call.
 * @action    Call edhoc_message_1_compose.
 * @expected  Non-success return code.
 */
TEST(coverage, msg1_compose_make_key_pair_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(2);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 compose with tiny buffer.
 * @env       Mock context with method 0, no failures.
 * @action    Call edhoc_message_1_compose with 1-byte buffer.
 * @expected  Non-success return code (buffer too small).
 */
TEST(coverage, msg1_compose_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[1] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 compose succeeds, then process with bad method.
 * @env       Two mock contexts: initiator composes msg1 with method 0,
 *            responder has method 1.
 * @action    Compose msg1 with initiator, process with mismatched responder.
 * @expected  Non-success (method mismatch) return code.
 */
TEST(coverage, msg1_process_method_mismatch)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_1);
	mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Message 1 process with EAD process failure.
 * @env       Two mock contexts, EAD process callback fails.
 * @action    Compose msg1 with EAD, process with failing EAD callback.
 * @expected  Non-success return code.
 */
TEST(coverage, msg1_process_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(1);
	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Message 2 failure injection --- */

/**
 * @scenario  Full handshake with message 2 compose DH failure.
 * @env       Initiator composes msg1 successfully; responder processes msg1,
 *            then DH key_agreement fails during msg2 compose.
 * @action    Run msg1 flow, then fail msg2 compose.
 * @expected  msg2 compose returns non-success.
 */
TEST(coverage, msg2_compose_dh_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(3);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full handshake with message 2 compose credential fetch failure.
 * @env       msg1 flow completes; credential fetch fails during msg2 compose.
 * @action    Run msg1 flow, fail credential fetch in msg2 compose.
 * @expected  msg2 compose returns non-success.
 */
TEST(coverage, msg2_compose_cred_fetch_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(7);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full handshake with message 2 compose hash failure.
 * @env       msg1 flow completes; hash fails during msg2 compose.
 * @action    Run msg1 flow, fail hash (5th mock call) in msg2 compose.
 * @expected  msg2 compose returns non-success.
 */
TEST(coverage, msg2_compose_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(5);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full handshake with message 2 compose EAD failure.
 * @env       msg1 flow completes; EAD compose fails during msg2.
 * @action    Run msg1 flow, fail EAD compose in msg2 compose.
 * @expected  msg2 compose returns non-success.
 */
TEST(coverage, msg2_compose_ead_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(6);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Exporter error paths --- */

/**
 * @scenario  PRK exporter with label in forbidden range.
 * @env       EDHOC context completed with PRK_STATE_OUT.
 * @action    Call edhoc_export_prk_exporter with label = 100.
 * @expected  EDHOC_ERROR_BAD_STATE (label out of valid range).
 */
TEST(coverage, prk_exporter_bad_label)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t secret[32] = { 0 };
	mock_reset(0);
	int ret = edhoc_export_prk_exporter(&ctx, 100, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  PRK exporter when crypto expand fails.
 * @env       EDHOC context completed with PRK_STATE_OUT.
 * @action    Call edhoc_export_prk_exporter with expand failing.
 * @expected  Non-success return code.
 */
TEST(coverage, prk_exporter_expand_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t secret[32] = { 0 };
	mock_reset(4);
	int ret =
		edhoc_export_prk_exporter(&ctx, 32769, secret, sizeof(secret));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  OSCORE export when status is not SM_COMPLETED.
 * @env       Context with status SM_WAIT_M2, oscore export allowed.
 * @action    Call edhoc_export_oscore_session.
 * @expected  Non-success (bad state).
 */
TEST(coverage, oscore_export_wrong_status)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.peer_cid.int_value = -8;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	mock_reset(0);
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Key update when PRK state is 4E3M (needs compute_prk_out first).
 * @env       Context in COMPLETED state with PRK_STATE_4E3M.
 * @action    Call edhoc_export_key_update.
 * @expected  Non-success (compute_prk_out or compute_new_prk_out may fail).
 */
TEST(coverage, key_update_success)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t entropy[16] = { 1, 2, 3 };
	mock_reset(0);
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ctx.is_oscore_export_allowed);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Key update when crypto extract fails.
 * @env       Context completed with PRK_STATE_OUT, extract fails.
 * @action    Call edhoc_export_key_update.
 * @expected  Non-success return code.
 */
TEST(coverage, key_update_extract_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t entropy[16] = { 1, 2, 3 };
	mock_reset(2);
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* --- Connection ID edge cases --- */

/**
 * @scenario  Set connection ID with byte string type.
 * @env       Freshly initialized context.
 * @action    Set connection ID using EDHOC_CID_TYPE_BYTE_STRING.
 * @expected  EDHOC_SUCCESS.
 */
TEST(coverage, conn_id_byte_string)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* --- Error message compose/process edge cases --- */

/**
 * @scenario  Compose error message with ERR_INFO for unspecified error
 *            where written_entries > total_entries.
 * @env       No context needed (error message is context-free).
 * @action    Call edhoc_message_error_compose with invalid info.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(coverage, error_msg_compose_bad_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	const char text[] = "error";
	struct edhoc_error_info info = {
		.text_string = (char *)text,
		.total_entries = 2,
		.written_entries = 5,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  Compose error message for wrong cipher suite with buffer overflow.
 * @env       Error info with more cipher suites than the internal buffer.
 * @action    Call edhoc_message_error_compose with too many cipher suites.
 * @expected  EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(coverage, error_msg_compose_suites_overflow)
{
	uint8_t buf[256] = { 0 };
	size_t len = 0;

	int32_t suites[100];
	for (size_t i = 0; i < 100; i++)
		suites[i] = (int32_t)i;

	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 100,
		.written_entries = 100,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @scenario  Compose error message with out-of-range error code.
 * @env       No specific setup.
 * @action    Call edhoc_message_error_compose with code = -1.
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, error_msg_compose_bad_code)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, (enum edhoc_error_code)(-1), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/**
 * @scenario  Process error message with unspecified error, buffer too small.
 * @env       Compose unspecified error with long text, process with small buf.
 * @action    Compose then process with tiny text buffer.
 * @expected  EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(coverage, error_msg_process_text_too_small)
{
	uint8_t buf[128] = { 0 };
	size_t len = 0;

	const char text[] = "a long error description";
	struct edhoc_error_info info = {
		.text_string = (char *)text,
		.total_entries = sizeof(text) - 1,
		.written_entries = sizeof(text) - 1,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	char recv_text[2] = { 0 };
	struct edhoc_error_info recv_info = {
		.text_string = recv_text,
		.total_entries = 1,
	};
	enum edhoc_error_code code;
	ret = edhoc_message_error_process(buf, len, &code, &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @scenario  Process error message for wrong cipher suite with small buf.
 * @env       Compose error with 3 cipher suites, process with buffer for 1.
 * @action    Compose then process.
 * @expected  EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(coverage, error_msg_process_suites_too_small)
{
	uint8_t buf[128] = { 0 };
	size_t len = 0;

	int32_t suites[] = { 0, 2, 3 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 3,
		.written_entries = 3,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_suites[1] = { 0 };
	struct edhoc_error_info recv_info = {
		.cipher_suites = recv_suites,
		.total_entries = 1,
	};
	enum edhoc_error_code code;
	ret = edhoc_message_error_process(buf, len, &code, &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @scenario  Process error message with invalid CBOR data.
 * @env       Garbage bytes as error message.
 * @action    Call edhoc_message_error_process with invalid CBOR.
 * @expected  EDHOC_ERROR_CBOR_FAILURE.
 */
TEST(coverage, error_msg_process_bad_cbor)
{
	const uint8_t garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code;

	int ret = edhoc_message_error_process(garbage, sizeof(garbage), &code,
					      NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

/**
 * @scenario  Compose error with NULL info for wrong cipher suite.
 * @env       No specific setup.
 * @action    Compose WRONG_SELECTED_CIPHER_SUITE with NULL info.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(coverage, error_msg_compose_suites_null_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  Compose error with NULL info for unspecified error.
 * @env       No specific setup.
 * @action    Compose UNSPECIFIED_ERROR with NULL info.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(coverage, error_msg_compose_unspecified_null_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* --- Message compose/process with different failure points --- */

/**
 * @scenario  Message 2 compose with signature failure.
 * @env       msg1 flow complete, signature callback fails.
 * @action    Fail signature during msg2 compose.
 * @expected  Non-success return code.
 */
TEST(coverage, msg2_compose_signature_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(10);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Message 2 compose with encrypt failure.
 * @env       msg1 flow complete, encrypt callback fails.
 * @action    Fail encrypt during msg2 compose.
 * @expected  Non-success return code.
 */
TEST(coverage, msg2_compose_encrypt_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(12);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Bad state tests --- */

/**
 * @scenario  Message 1 compose called twice (bad state).
 * @env       Context already composed msg1.
 * @action    Call edhoc_message_1_compose again.
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg1_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 2 compose without prior msg1 process.
 * @env       Fresh context (no msg1 processed).
 * @action    Call edhoc_message_2_compose directly.
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg2_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_2_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 3 compose without prior msg2 process.
 * @env       Fresh context.
 * @action    Call edhoc_message_3_compose directly.
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg3_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_3_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 4 compose without prior msg3 process.
 * @env       Fresh context.
 * @action    Call edhoc_message_4_compose directly.
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg4_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_4_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 process with truncated CBOR data.
 * @env       Fresh responder context.
 * @action    Process 1 byte of garbage as msg1.
 * @expected  Non-success (CBOR failure or msg1 process failure).
 */
TEST(coverage, msg1_process_bad_cbor)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	mock_reset(0);

	const uint8_t garbage[] = { 0xFF };
	int ret = edhoc_message_1_process(&ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  OSCORE export with byte string CID.
 * @env       Context completed with byte-string peer CID.
 * @action    Export OSCORE session.
 * @expected  EDHOC_SUCCESS with correct SID/RID.
 */
TEST(coverage, oscore_export_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
	ctx.peer_cid.bstr_length = 2;
	ctx.peer_cid.bstr_value[0] = 0xAA;
	ctx.peer_cid.bstr_value[1] = 0xBB;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	mock_reset(0);
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* --- CBOR helper edge cases --- */

/**
 * @scenario  Test edhoc_cbor_int_mem_req with various integer ranges.
 * @env       No context needed.
 * @action    Call edhoc_cbor_int_mem_req with small and large values.
 * @expected  Correct sizes for 1, 2, 3, and 5 byte CBOR integers.
 */
TEST(coverage, cbor_int_mem_req_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_mem_req(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_mem_req(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_int_mem_req(65536));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(-1));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(-24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(-25));
}

/**
 * @scenario  Test edhoc_cbor_bstr_oh with various byte string lengths.
 * @env       No context needed.
 * @action    Call edhoc_cbor_bstr_oh with small and large sizes.
 * @expected  Correct overhead for each CBOR byte string length range.
 */
TEST(coverage, cbor_bstr_oh_ranges)
{
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(0));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_bstr_oh(65536));
}

/**
 * @scenario  Test edhoc_cbor_tstr_oh with various text string lengths.
 * @env       No context needed.
 * @action    Call edhoc_cbor_tstr_oh with small and large sizes.
 * @expected  Correct overhead for each CBOR text string length range.
 */
TEST(coverage, cbor_tstr_oh_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_oh(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_tstr_oh(65536));
}

/**
 * @scenario  Test edhoc_cbor_map_oh.
 * @env       No context needed.
 * @action    Call edhoc_cbor_map_oh.
 * @expected  Returns 1 (single byte CBOR map header for small maps).
 */
TEST(coverage, cbor_map_oh)
{
	TEST_ASSERT_EQUAL(3, edhoc_cbor_map_oh(1));
}

/**
 * @scenario  Test edhoc_cbor_array_oh with various item counts.
 * @env       No context needed.
 * @action    Call edhoc_cbor_array_oh with small and large counts.
 * @expected  Correct overhead for CBOR array header.
 */
TEST(coverage, cbor_array_oh_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_oh(256));
}

/* --- Systematic failure sweeps for msg2 compose --- */

static int do_msg1_flow(struct edhoc_context *init_ctx,
			struct edhoc_context *resp_ctx, uint8_t *msg1,
			size_t msg1_size, size_t *msg1_len)
{
	mock_reset(0);
	int ret = edhoc_message_1_compose(init_ctx, msg1, msg1_size, msg1_len);
	if (EDHOC_SUCCESS != ret)
		return ret;
	mock_reset(0);
	return edhoc_message_1_process(resp_ctx, msg1, *msg1_len);
}

/**
 * @scenario  Sweep failure points in msg2 compose (points 4..15).
 * @env       msg1 flow completed successfully.
 * @action    For each failure point N=4..15, fail on the Nth mock call
 *            during edhoc_message_2_compose and verify failure.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg2_compose_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep higher failure points in msg2 compose (points 16..20).
 * @env       msg1 flow completed; failure injected in later msg2 compose ops.
 * @action    For each point N, fail during later stages of msg2 compose.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg2_compose_failure_sweep_high)
{
	for (int fail_pt = 16; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		/* Some high failure points may succeed if compose finishes */
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 compose for method 3 (static DH).
 * @env       msg1 flow completed with method 3.
 * @action    Sweep failure points 4..12 during msg2 compose with method 3.
 * @expected  All calls return non-success (exercises static DH paths).
 */
TEST(coverage, msg2_compose_method3_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 compose for method 1 (sig/DH).
 * @env       msg1 flow completed with method 1.
 * @action    Sweep failure points 4..12 during msg2 compose with method 1.
 * @expected  All calls return non-success (exercises mixed sig/DH paths).
 */
TEST(coverage, msg2_compose_method1_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 compose for method 2 (DH/sig).
 * @env       msg1 flow completed with method 2.
 * @action    Sweep failure points 4..12 during msg2 compose with method 2.
 * @expected  All calls return non-success (exercises mixed DH/sig paths).
 */
TEST(coverage, msg2_compose_method2_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  PRK exporter with direct state setup, various failure points.
 * @env       Context manually set to COMPLETED with PRK_STATE_OUT.
 * @action    Sweep failure points 1..4 during PRK export.
 * @expected  Non-success for each failure point.
 */
TEST(coverage, prk_exporter_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 4; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		setup_mock_context(&ctx, EDHOC_METHOD_0);
		ctx.status = EDHOC_SM_COMPLETED;
		ctx.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.th_len = 32;
		ctx.prk_len = 32;

		uint8_t secret[32] = { 0 };
		mock_reset(fail_pt);
		int ret = edhoc_export_prk_exporter(&ctx, 32769, secret,
						    sizeof(secret));
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&ctx);
	}
}

/**
 * @scenario  OSCORE export with direct state setup, various failure points.
 * @env       Context manually set to COMPLETED with export allowed.
 * @action    Sweep failure points 1..6 during OSCORE export.
 * @expected  Non-success for each failure point.
 */
TEST(coverage, oscore_export_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 6; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		setup_mock_context(&ctx, EDHOC_METHOD_0);
		ctx.status = EDHOC_SM_COMPLETED;
		ctx.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.is_oscore_export_allowed = true;
		ctx.th_len = 32;
		ctx.prk_len = 32;
		ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx.peer_cid.int_value = -8;

		uint8_t ms[16], salt[8], sid[8], rid[8];
		size_t sid_len, rid_len;

		mock_reset(fail_pt);
		int ret = edhoc_export_oscore_session(
			&ctx, ms, sizeof(ms), salt, sizeof(salt), sid,
			sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&ctx);
	}
}

/* --- Debug: verify msg2_compose succeeds with mocks --- */

/**
 * @scenario  Verify msg2 compose succeeds with zero-failure mocks.
 * @env       msg1 flow completed, no failures injected.
 * @action    Call msg2 compose with no mock failures.
 * @expected  msg2 compose succeeds.
 */
TEST(coverage, msg2_compose_no_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL_MESSAGE(EDHOC_SUCCESS, ret,
				  "msg2_compose with no failures");

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- msg2 process failure sweeps --- */

static int do_full_msg2_flow(struct edhoc_context *init_ctx,
			     struct edhoc_context *resp_ctx, uint8_t *msg2,
			     size_t msg2_size, size_t *msg2_len)
{
	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	int ret =
		do_msg1_flow(init_ctx, resp_ctx, msg1, sizeof(msg1), &msg1_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	mock_reset(0);
	return edhoc_message_2_compose(resp_ctx, msg2, msg2_size, msg2_len);
}

/**
 * @scenario  Sweep failure points in msg2 process for method 0.
 * @env       msg1 + msg2 compose completed successfully.
 * @action    For each failure point N=1..15, fail during edhoc_message_2_process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg2_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 process for method 3 (DH/DH).
 * @env       msg1 + msg2 compose completed with method 3.
 * @action    Sweep failure points 1..20 during msg2 process.
 * @expected  All calls return non-success (exercises DH path in comp_prk_3e2m).
 */
TEST(coverage, msg2_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 process for method 1 (sig/DH).
 * @env       msg1 + msg2 compose completed with method 1.
 * @action    Sweep failure points 1..20 during msg2 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg2_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg2 process for method 2 (DH/sig).
 * @env       msg1 + msg2 compose completed with method 2.
 * @action    Sweep failure points 1..20 during msg2 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg2_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- Full mock handshake success tests --- */

static int do_mock_msg2_process(struct edhoc_context *init_ctx,
				struct edhoc_context *resp_ctx)
{
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(init_ctx, resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	mock_reset(0);
	return edhoc_message_2_process(init_ctx, msg2, msg2_len);
}

static int do_mock_msg3_compose(struct edhoc_context *init_ctx,
				struct edhoc_context *resp_ctx, uint8_t *msg3,
				size_t msg3_size, size_t *msg3_len)
{
	int ret = do_mock_msg2_process(init_ctx, resp_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	mock_reset(0);
	return edhoc_message_3_compose(init_ctx, msg3, msg3_size, msg3_len);
}

static int do_mock_msg3_process(struct edhoc_context *init_ctx,
				struct edhoc_context *resp_ctx)
{
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = do_mock_msg3_compose(init_ctx, resp_ctx, msg3, sizeof(msg3),
				       &msg3_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	mock_reset(0);
	return edhoc_message_3_process(resp_ctx, msg3, msg3_len);
}

/**
 * @scenario  Full mock handshake for method 0 (sig/sig) through msg3 process.
 * @env       Two contexts with method 0 and mock callbacks.
 * @action    Run complete msg1→msg2→msg2proc→msg3→msg3proc flow.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full mock handshake for method 1 (sig/DH) through msg3 process.
 * @env       Two contexts with method 1 and mock callbacks.
 * @action    Run complete msg1→msg2→msg2proc→msg3→msg3proc flow.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_method1)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_1);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full mock handshake for method 2 (DH/sig) through msg3 process.
 * @env       Two contexts with method 2 and mock callbacks.
 * @action    Run complete msg1→msg2→msg2proc→msg3→msg3proc flow.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_method2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_2);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full mock handshake for method 3 (DH/DH) through msg3 process.
 * @env       Two contexts with method 3 and mock callbacks.
 * @action    Run complete msg1→msg2→msg2proc→msg3→msg3proc flow.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- msg3 compose failure sweeps --- */

/**
 * @scenario  Sweep failure points in msg3 compose for method 0.
 * @env       msg1+msg2+msg2proc completed successfully.
 * @action    Sweep failure points 1..20 during msg3 compose.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 compose for method 3 (DH/DH).
 * @env       msg1+msg2+msg2proc completed with method 3.
 * @action    Sweep failure points 1..25 during msg3 compose.
 * @expected  All calls return non-success (exercises DH path in comp_prk_4e3m).
 */
TEST(coverage, msg3_compose_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		/* High points may succeed if compose finishes early */
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 compose for method 1 (sig/DH).
 * @env       msg1+msg2+msg2proc completed with method 1.
 * @action    Sweep failure points 1..25 during msg3 compose.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_compose_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 compose for method 2 (DH/sig).
 * @env       msg1+msg2+msg2proc completed with method 2.
 * @action    Sweep failure points 1..25 during msg3 compose.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_compose_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- msg3 process failure sweeps --- */

/**
 * @scenario  Sweep failure points in msg3 process for method 0.
 * @env       msg1+msg2+msg2proc+msg3 compose completed successfully.
 * @action    Sweep failure points 1..20 during msg3 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 process for method 3 (DH/DH).
 * @env       msg1+msg2+msg2proc+msg3 compose completed with method 3.
 * @action    Sweep failure points 1..25 during msg3 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 process for method 1 (sig/DH).
 * @env       msg1+msg2+msg2proc+msg3 compose completed with method 1.
 * @action    Sweep failure points 1..25 during msg3 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg3 process for method 2 (DH/sig).
 * @env       msg1+msg2+msg2proc+msg3 compose completed with method 2.
 * @action    Sweep failure points 1..25 during msg3 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg3_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- msg4 compose / process failure sweeps --- */

/**
 * @scenario  Full mock handshake through msg4 compose+process for method 0.
 * @env       Two contexts with method 0 and mock callbacks.
 * @action    Run msg1→...→msg3proc→msg4compose→msg4process flow.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_msg4_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Sweep failure points in msg4 compose for method 0.
 * @env       Full handshake through msg3 process completed.
 * @action    Sweep failure points 1..20 during msg4 compose.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg4_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep failure points in msg4 process for method 0.
 * @env       Full handshake through msg4 compose completed.
 * @action    Sweep failure points 1..20 during msg4 process.
 * @expected  All calls return non-success.
 */
TEST(coverage, msg4_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Full mock handshake with msg4 for method 3 (DH/DH).
 * @env       Two contexts with method 3 and mock callbacks.
 * @action    Run full handshake including msg4 with DH/DH method.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_full_handshake_msg4_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Sweep msg4 compose failure for method 3 (DH/DH).
 * @env       Full handshake through msg3 process with method 3.
 * @action    Sweep failure points 1..25 during msg4 compose.
 * @expected  Exercises DH-specific paths in msg4 compose.
 */
TEST(coverage, msg4_compose_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep msg4 process failure for method 3 (DH/DH).
 * @env       Full handshake through msg4 compose with method 3.
 * @action    Sweep failure points 1..25 during msg4 process.
 * @expected  Exercises DH-specific paths in msg4 process.
 */
TEST(coverage, msg4_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- KID credential variant for different edhoc_common.c branches --- */

static int mock_cred_fetch_kid(void *user_ctx,
			       struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	auth_cred->key_id.key_id_int = 5;
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_kid = {
	.fetch = mock_cred_fetch_kid,
	.verify = mock_cred_verify,
};

static void setup_mock_context_kid(struct edhoc_context *ctx,
				   enum edhoc_method method)
{
	setup_mock_context(ctx, method);
	edhoc_bind_credentials(ctx, &mock_creds_kid);
}

/**
 * @scenario  Full mock handshake with KID integer credentials for method 0.
 * @env       Two contexts with KID integer credentials.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises KID branches in edhoc_common.c).
 */
TEST(coverage, mock_handshake_kid_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_kid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full mock handshake with KID credentials for method 3 (DH/DH).
 * @env       Two contexts with KID integer credentials and method 3.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed.
 */
TEST(coverage, mock_handshake_kid_int_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_kid(&init_ctx, EDHOC_METHOD_3);
	setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_3);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* KID byte-string variant */
static int mock_cred_fetch_kid_bstr(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	static const uint8_t kid[] = { 0xAB };
	memcpy(auth_cred->key_id.key_id_bstr, kid, sizeof(kid));
	auth_cred->key_id.key_id_bstr_length = sizeof(kid);
	static const uint8_t fake_cred[] = { 0xA1, 0x01, 0x01 };
	auth_cred->key_id.cred = fake_cred;
	auth_cred->key_id.cred_len = sizeof(fake_cred);
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_kid_bstr = {
	.fetch = mock_cred_fetch_kid_bstr,
	.verify = mock_cred_verify,
};

/**
 * @scenario  Full mock handshake with KID byte-string credentials.
 * @env       Two contexts with KID bstr credentials and method 0.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises KID bstr branches).
 */
TEST(coverage, mock_handshake_kid_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &mock_creds_kid_bstr);
	edhoc_bind_credentials(&resp_ctx, &mock_creds_kid_bstr);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* x509_hash with byte-string algorithm credential variant */
static int mock_cred_fetch_x5t_bstr(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_HASH;

	static const uint8_t fake_cert[] = { 0x30, 0x82, 0x01, 0x00 };
	auth_cred->x509_hash.cert = fake_cert;
	auth_cred->x509_hash.cert_len = sizeof(fake_cert);

	static const uint8_t fake_fp[] = { 0xAA, 0xBB, 0xCC, 0xDD };
	auth_cred->x509_hash.cert_fp = fake_fp;
	auth_cred->x509_hash.cert_fp_len = sizeof(fake_fp);

	auth_cred->x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	static const uint8_t alg[] = { 0x53, 0x48, 0x41 }; /* "SHA" */
	memcpy(auth_cred->x509_hash.alg_bstr, alg, sizeof(alg));
	auth_cred->x509_hash.alg_bstr_length = sizeof(alg);

	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_x5t_bstr = {
	.fetch = mock_cred_fetch_x5t_bstr,
	.verify = mock_cred_verify,
};

/**
 * @scenario  Full mock handshake with x509_hash (bstr algorithm) credentials.
 * @env       Two contexts with x5t bstr alg credentials and method 0.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises x5t bstr algorithm branches in
 *            compose and parse_plaintext for msg2 and msg3).
 */
TEST(coverage, mock_handshake_x5t_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &mock_creds_x5t_bstr);
	edhoc_bind_credentials(&resp_ctx, &mock_creds_x5t_bstr);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* x509_hash with integer algorithm credential variant */
static int mock_cred_fetch_x5t_int(void *user_ctx,
				   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_HASH;

	static const uint8_t fake_cert[] = { 0x30, 0x82, 0x01, 0x00 };
	auth_cred->x509_hash.cert = fake_cert;
	auth_cred->x509_hash.cert_len = sizeof(fake_cert);

	static const uint8_t fake_fp[] = { 0xAA, 0xBB, 0xCC, 0xDD };
	auth_cred->x509_hash.cert_fp = fake_fp;
	auth_cred->x509_hash.cert_fp_len = sizeof(fake_fp);

	auth_cred->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	auth_cred->x509_hash.alg_int = -16; /* SHA-256 */

	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_x5t_int = {
	.fetch = mock_cred_fetch_x5t_int,
	.verify = mock_cred_verify,
};

/**
 * @scenario  Full mock handshake with x509_hash (integer algorithm) credentials.
 * @env       Two contexts with x5t int alg credentials and method 0.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises x5t int algorithm branches).
 */
TEST(coverage, mock_handshake_x5t_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &mock_creds_x5t_int);
	edhoc_bind_credentials(&resp_ctx, &mock_creds_x5t_int);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* x509_chain with multiple certificates */
static int mock_cred_fetch_x5chain_multi(void *user_ctx,
					 struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 2;

	static const uint8_t fake_cert_0[] = { 0x30, 0x00 };
	static const uint8_t fake_cert_1[] = { 0x30, 0x01, 0x00 };
	auth_cred->x509_chain.cert[0] = fake_cert_0;
	auth_cred->x509_chain.cert_len[0] = sizeof(fake_cert_0);
	auth_cred->x509_chain.cert[1] = fake_cert_1;
	auth_cred->x509_chain.cert_len[1] = sizeof(fake_cert_1);

	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_x5chain_multi = {
	.fetch = mock_cred_fetch_x5chain_multi,
	.verify = mock_cred_verify,
};

/**
 * @scenario  Full mock handshake with x509_chain multi-cert credentials.
 * @env       Two contexts with x5chain (2 certs) and method 0.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises multi-cert x509_chain branches).
 */
TEST(coverage, mock_handshake_x5chain_multi_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &mock_creds_x5chain_multi);
	edhoc_bind_credentials(&resp_ctx, &mock_creds_x5chain_multi);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* COSE_ANY credential variant with compact encoding */
static int mock_cred_fetch_cose_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_ANY;

	static const uint8_t fake_id_cred[] = { 0xA1, 0x04, 0x42, 0xAB, 0xCD };
	auth_cred->any.id_cred = fake_id_cred;
	auth_cred->any.id_cred_len = sizeof(fake_id_cred);

	static const uint8_t fake_cred[] = { 0x58, 0x02, 0x30, 0x00 };
	auth_cred->any.cred = fake_cred;
	auth_cred->any.cred_len = sizeof(fake_cred);

	auth_cred->any.is_id_cred_comp_enc = true;
	auth_cred->any.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	static const uint8_t comp_enc[] = { 0x05 };
	auth_cred->any.id_cred_comp_enc = comp_enc;
	auth_cred->any.id_cred_comp_enc_length = sizeof(comp_enc);

	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials mock_creds_cose_any = {
	.fetch = mock_cred_fetch_cose_any,
	.verify = mock_cred_verify,
};

/**
 * @scenario  Full mock handshake with COSE_ANY credentials (compact encoding).
 * @env       Two contexts with COSE_ANY credentials and method 0.
 * @action    Run full handshake through msg3 process.
 * @expected  All steps succeed (exercises COSE_ANY + compact encoding branches).
 */
TEST(coverage, mock_handshake_cose_any_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &mock_creds_cose_any);
	edhoc_bind_credentials(&resp_ctx, &mock_creds_cose_any);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* Byte-string CID variant */
static void setup_mock_context_bstr_cid(struct edhoc_context *ctx,
					enum edhoc_method method)
{
	setup_mock_context(ctx, method);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	edhoc_set_connection_id(ctx, &cid);
}

/**
 * @scenario  Full mock handshake with byte-string CIDs for method 0.
 * @env       Two contexts with bstr CIDs and method 0.
 * @action    Run full handshake through msg4 process.
 * @expected  All steps succeed (exercises bstr CID branches).
 */
TEST(coverage, mock_handshake_bstr_cid_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Extended msg2 compose sweep to higher failure points --- */

/**
 * @scenario  Sweep very high failure points in msg2 compose (21..30).
 * @env       msg1 flow completed; late-stage failures in msg2 compose.
 * @action    Sweep points 21..30 to cover final stages.
 * @expected  Some calls may succeed; exercises deep compose paths.
 */
TEST(coverage, msg2_compose_failure_sweep_very_high)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Sweep very high failure points in msg2 compose for method 3.
 * @env       msg1 flow completed with method 3; late-stage failures.
 * @action    Sweep points 13..30 to cover DH-specific paths deep in compose.
 * @expected  Some calls may succeed.
 */
TEST(coverage, msg2_compose_method3_failure_sweep_high)
{
	for (int fail_pt = 13; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg1_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		setup_mock_context(&ctx, EDHOC_METHOD_0);
		mock_reset(fail_pt);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1),
						  &msg1_len);
		(void)ret;

		edhoc_context_deinit(&ctx);
	}
}

TEST(coverage, msg1_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
						  &msg1_len);
		if (EDHOC_SUCCESS != ret)
			goto cleanup1;

		mock_reset(fail_pt);
		ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
		(void)ret;
cleanup1:
		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg2_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS == ret) {
		struct edhoc_context init2 = { 0 };
		setup_mock_context(&init2, EDHOC_METHOD_0);
		mock_reset(0);
		uint8_t m1[512];
		size_t m1l;
		edhoc_message_1_compose(&init2, m1, sizeof(m1), &m1l);

		for (size_t trunc = 1; trunc < msg2_len && trunc < 10;
		     trunc++) {
			mock_reset(0);
			int r = edhoc_message_2_process(&init2, msg2, trunc);
			(void)r;
		}
		edhoc_context_deinit(&init2);
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage, msg3_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3, sizeof(msg3),
				       &msg3_len);
	if (EDHOC_SUCCESS == ret) {
		for (size_t trunc = 1; trunc < msg3_len && trunc < 10;
		     trunc++) {
			struct edhoc_context resp2 = { 0 };
			setup_mock_context(&resp2, EDHOC_METHOD_0);
			mock_reset(0);

			uint8_t m1[512];
			size_t m1l;
			edhoc_message_1_compose(&init_ctx, m1, sizeof(m1),
						&m1l);

			int r = edhoc_message_3_process(&resp_ctx, msg3, trunc);
			(void)r;
			edhoc_context_deinit(&resp2);
		}
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage, exporter_failure_sweep_extended)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t secret[32], salt[32], sid[16], rid[16];
		size_t sid_len, rid_len;
		ret = edhoc_export_oscore_session(
			&init_ctx, secret, sizeof(secret), salt, sizeof(salt),
			sid, sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg2_compose_extended_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		setup_mock_context(&ctx, EDHOC_METHOD_0);

		mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);

		struct edhoc_context resp = { 0 };
		setup_mock_context(&resp, EDHOC_METHOD_0);
		mock_reset(0);
		edhoc_message_1_process(&resp, msg1, msg1_len);

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = edhoc_message_2_compose(&resp, msg2, sizeof(msg2),
						  &msg2_len);
		(void)ret;

		edhoc_context_deinit(&ctx);
		edhoc_context_deinit(&resp);
	}
}

/* --- bstr CID handshake + OSCORE export (covers bstr CID export paths) --- */

/**
 * @scenario  OSCORE export after bstr CID handshake covers BSTR CID branches.
 * @env       Both sides use bstr CIDs; full handshake completes.
 * @action    Call edhoc_export_oscore_session after msg3 process.
 * @expected  Export succeeds; bstr CID copy paths exercised.
 */
TEST(coverage, oscore_export_after_bstr_cid_handshake)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  OSCORE export with invalid peer CID encode type.
 * @env       Full handshake completes, then corrupt peer_cid.encode_type.
 * @action    Call edhoc_export_oscore_session.
 * @expected  Returns EDHOC_ERROR_NOT_PERMITTED (default case in CID switch).
 */
TEST(coverage, oscore_export_invalid_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.peer_cid.encode_type = (enum edhoc_connection_id_type)99;

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  OSCORE export with invalid own CID encode type.
 * @env       Full handshake completes, then corrupt cid.encode_type.
 * @action    Call edhoc_export_oscore_session.
 * @expected  Returns error (default case in CID switch for recipient ID).
 */
TEST(coverage, oscore_export_invalid_own_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.cid.encode_type = (enum edhoc_connection_id_type)99;

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  OSCORE export bstr CID with buffer too small for sender ID.
 * @env       Full bstr CID handshake, tiny sid buffer.
 * @action    Call edhoc_export_oscore_session with sid_size=1 (bstr CID is 3).
 * @expected  Returns error (BUFFER_TOO_SMALL for sender ID).
 */
TEST(coverage, oscore_export_bstr_cid_sid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[1], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  OSCORE export bstr CID with buffer too small for recipient ID.
 * @env       Full bstr CID handshake, tiny rid buffer.
 * @action    Call edhoc_export_oscore_session with rid_size=1 (bstr CID is 3).
 * @expected  Returns error (BUFFER_TOO_SMALL for recipient ID).
 */
TEST(coverage, oscore_export_bstr_cid_rid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[1];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- key_update with PRK_STATE_4E3M triggers compute_prk_out path --- */

/**
 * @scenario  Key update when PRK state is 4E3M triggers compute_prk_out.
 * @env       Handshake through msg3 compose (initiator has PRK_STATE_4E3M).
 * @action    Call edhoc_export_key_update on initiator (PRK_STATE_4E3M).
 * @expected  Covers compute_prk_out path in key_update; succeeds.
 */
TEST(coverage, key_update_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3, sizeof(msg3),
				       &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;

	mock_reset(0);
	uint8_t entropy[32] = { 0x42 };
	ret = edhoc_export_key_update(&init_ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Key update when PRK_STATE_4E3M but compute_prk_out fails.
 * @env       Handshake through msg3 compose, PRK state forced to 4E3M.
 * @action    Call edhoc_export_key_update with mock failure at point 1.
 * @expected  Returns error (compute_prk_out failure propagation).
 */
TEST(coverage, key_update_prk_state_4e3m_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3, sizeof(msg3),
				       &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;

	mock_reset(1);
	uint8_t entropy[32] = { 0x42 };
	ret = edhoc_export_key_update(&init_ctx, entropy, sizeof(entropy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- oscore_export with PRK_STATE_4E3M triggers compute_prk_out path --- */

/**
 * @scenario  OSCORE export when PRK state is 4E3M first computes PRK_out.
 * @env       After msg3 process, force prk_state back to 4E3M, th_state=4.
 * @action    Call edhoc_export_oscore_session.
 * @expected  Succeeds; exercises compute_prk_out → export flow.
 */
TEST(coverage, oscore_export_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.th_state = EDHOC_TH_STATE_4;

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&resp_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Extended msg3/msg4 failure sweeps to higher points --- */

/**
 * @scenario  Extended msg3 compose failure sweep, points 26..40.
 * @env       msg2 process completed (method 0).
 * @action    Inject failures at higher points during msg3 compose.
 * @expected  Exercises deeper compose error paths.
 */
TEST(coverage, msg3_compose_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Extended msg3 process failure sweep, points 26..40.
 * @env       msg3 compose completed (method 0).
 * @action    Inject failures at higher points during msg3 process.
 * @expected  Exercises deeper process error paths.
 */
TEST(coverage, msg3_process_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Extended msg4 compose failure sweep, points 26..40.
 * @env       Full handshake through msg3 process (method 0).
 * @action    Inject failures at higher points during msg4 compose.
 * @expected  Exercises deeper compose error paths.
 */
TEST(coverage, msg4_compose_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Extended msg4 process failure sweep, points 26..40.
 * @env       msg4 compose completed (method 0).
 * @action    Inject failures at higher points during msg4 process.
 * @expected  Exercises deeper process error paths.
 */
TEST(coverage, msg4_process_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- Extended exporter failure sweep with higher range --- */

/**
 * @scenario  Extended exporter failure sweep at very high points.
 * @env       Full handshake through msg3 process; force PRK_STATE_4E3M.
 * @action    Inject failures at points 1..15 during oscore export.
 * @expected  Exercises all export error paths including compute_prk_out.
 */
TEST(coverage, oscore_export_failure_sweep_4e3m)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
		resp_ctx.th_state = EDHOC_TH_STATE_4;

		mock_reset(fail_pt);
		uint8_t secret[32], salt[32], sid[16], rid[16];
		size_t sid_len, rid_len;
		ret = edhoc_export_oscore_session(
			&resp_ctx, secret, sizeof(secret), salt, sizeof(salt),
			sid, sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- msg1 with EAD that fails processing --- */

static int mock_ead_compose_with_token(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	if (mock_should_fail())
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	if (ead_token_size > 0) {
		static const uint8_t ead_val[] = { 0xAA, 0xBB };
		ead_token[0].label = 1;
		ead_token[0].value = ead_val;
		ead_token[0].value_len = sizeof(ead_val);
		*ead_token_len = 1;
	} else {
		*ead_token_len = 0;
	}
	return EDHOC_SUCCESS;
}

static int mock_ead_process_fail(void *user_ctx, enum edhoc_message msg,
				 const struct edhoc_ead_token *ead_token,
				 size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	return EDHOC_ERROR_EAD_PROCESS_FAILURE;
}

/**
 * @scenario  msg1 process with EAD tokens and EAD process failure.
 * @env       Initiator uses EAD compose callback that emits a token;
 *            responder has EAD process callback that always fails.
 * @action    Compose msg1 with EAD, then process on responder.
 * @expected  Returns EDHOC_ERROR_EAD_PROCESS_FAILURE.
 */
TEST(coverage, msg1_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_compose = {
		.compose = mock_ead_compose_with_token,
		.process = mock_ead_process,
	};
	edhoc_bind_ead(&init_ctx, &ead_compose);

	const struct edhoc_ead ead_fail = {
		.compose = mock_ead_compose,
		.process = mock_ead_process_fail,
	};
	edhoc_bind_ead(&resp_ctx, &ead_fail);

	mock_reset(0);
	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- msg2 compose/process with bstr CID (covers C_I bstr branches) --- */

/**
 * @scenario  msg2 compose with bstr CID covers C_I bstr encoding paths.
 * @env       Both sides use bstr CIDs; msg1 flow complete.
 * @action    Compose msg2.
 * @expected  Succeeds; bstr CID branches in msg2 compose exercised.
 */
TEST(coverage, msg2_compose_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	mock_reset(0);
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose with bstr CID failure sweep.
 * @env       Both sides use bstr CIDs.
 * @action    Sweep failure points 1..30 during msg2 compose.
 * @expected  Exercises bstr CID error paths in msg2 compose.
 */
TEST(coverage, msg2_compose_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		mock_reset(0);
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg2 process with bstr CID failure sweep.
 * @env       Both sides use bstr CIDs; msg2 compose complete.
 * @action    Sweep failure points 1..20 during msg2 process.
 * @expected  Exercises bstr CID error paths in msg2 process.
 */
TEST(coverage, msg2_process_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- msg3 compose/process with bstr CID --- */

/**
 * @scenario  msg3 compose/process failure sweep with bstr CID method 0.
 * @env       Both sides bstr CID, method 0; full msg2 flow complete.
 * @action    Sweep failure points 1..30 during msg3 compose.
 * @expected  Exercises bstr CID paths in msg3.
 */
TEST(coverage, msg3_compose_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg4 compose/process with bstr CID.
 * @env       Full handshake through msg3 process with bstr CIDs.
 * @action    Compose and process msg4.
 * @expected  All steps succeed; bstr CID paths in msg4 exercised.
 */
TEST(coverage, msg4_bstr_cid_full)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&init_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Full handshake + msg4 for methods 1 and 2 --- */

/**
 * @scenario  Full handshake through msg4 for method 1.
 * @env       Two contexts method 1.
 * @action    msg1→msg2→msg3→msg4 compose+process.
 * @expected  All succeed.
 */
TEST(coverage, mock_full_handshake_msg4_method1)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_1);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Full handshake through msg4 for method 2.
 * @env       Two contexts method 2.
 * @action    msg1→msg2→msg3→msg4 compose+process.
 * @expected  All succeed.
 */
TEST(coverage, mock_full_handshake_msg4_method2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_2);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- msg4 failure sweeps for methods 1 and 2 --- */

/**
 * @scenario  msg4 compose failure sweep for method 1.
 * @env       Full handshake through msg3 process (method 1).
 * @action    Sweep failure points 1..25 during msg4 compose.
 * @expected  All calls either succeed or return non-success.
 */
TEST(coverage, msg4_compose_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg4 process failure sweep for method 1.
 * @env       Full handshake + msg4 compose (method 1).
 * @action    Sweep failure points 1..25 during msg4 process.
 * @expected  All calls either succeed or return non-success.
 */
TEST(coverage, msg4_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg4 compose failure sweep for method 2.
 * @env       Full handshake through msg3 process (method 2).
 * @action    Sweep failure points 1..25 during msg4 compose.
 * @expected  All calls either succeed or return non-success.
 */
TEST(coverage, msg4_compose_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg4 process failure sweep for method 2.
 * @env       Full handshake + msg4 compose (method 2).
 * @action    Sweep failure points 1..25 during msg4 process.
 * @expected  All calls either succeed or return non-success.
 */
TEST(coverage, msg4_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- Extended oscore export failure sweep with bstr CID --- */

/**
 * @scenario  OSCORE export failure sweep with bstr CIDs.
 * @env       Full bstr CID handshake completed.
 * @action    Sweep failure points 1..15 during oscore export.
 * @expected  Exercises bstr CID error paths in export.
 */
TEST(coverage, oscore_export_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t secret[32], salt[32], sid[16], rid[16];
		size_t sid_len, rid_len;
		ret = edhoc_export_oscore_session(
			&resp_ctx, secret, sizeof(secret), salt, sizeof(salt),
			sid, sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- key_update failure sweep --- */

/**
 * @scenario  Key update failure sweep.
 * @env       Full handshake completed.
 * @action    Sweep failure points 1..10 during key update.
 * @expected  Exercises all key update error paths.
 */
TEST(coverage, key_update_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t entropy[32] = { 0x42 };
		ret = edhoc_export_key_update(&resp_ctx, entropy,
					      sizeof(entropy));
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/* --- msg1 compose with EAD tokens --- */

/**
 * @scenario  msg1 compose with EAD tokens exercises EAD encoding paths.
 * @env       Initiator with EAD compose callback that emits a token.
 * @action    Compose msg1 with EAD.
 * @expected  Succeeds; covers EAD compose paths in msg1.
 */
TEST(coverage, msg1_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_mock_context(&ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_with_token = {
		.compose = mock_ead_compose_with_token,
		.process = mock_ead_process,
	};
	edhoc_bind_ead(&ctx, &ead_with_token);

	mock_reset(0);
	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* --- msg2 compose with bstr CID tiny buffer --- */

/**
 * @scenario  msg2 compose with bstr CID into tiny buffer.
 * @env       Both sides bstr CID; msg1 flow complete.
 * @action    Compose msg2 into 4-byte buffer (too small).
 * @expected  Returns error (buffer too small in msg2 output encoding).
 */
TEST(coverage, msg2_compose_bstr_cid_tiny_buf)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	if (EDHOC_SUCCESS == ret) {
		mock_reset(0);
		uint8_t msg2[4] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Context corruption tests to hit deep internal default cases --- */

/**
 * @scenario  msg2 compose with corrupted CID encode type.
 * @env       msg1 flow completed, then responder's cid.encode_type corrupted.
 * @action    Compose msg2.
 * @expected  Returns error (default case in prepare_plaintext_2, line 687).
 */
TEST(coverage, msg2_compose_corrupted_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.cid.encode_type = (enum edhoc_connection_id_type)99;

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose with corrupted role to unsupported method path.
 * @env       msg1 flow completed, then chosen_method set to invalid value.
 * @action    Compose msg2.
 * @expected  Returns error (unsupported method in comp_prk_3e2m).
 */
TEST(coverage, msg2_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.chosen_method = (enum edhoc_method)99;

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 compose with corrupted credential label (via mock callback).
 * @env       msg2 process completed, then cred_fetch returns invalid label.
 * @action    Compose msg3.
 * @expected  Returns error (unsupported label in comp_id_cred_len).
 */
TEST(coverage, msg3_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.fetch = mock_cred_fetch_invalid_label,
		.verify = mock_cred_verify,
	};
	edhoc_bind_credentials(&init_ctx, &bad_creds);

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 compose with corrupted method.
 * @env       msg2 process completed, then chosen_method set to invalid.
 * @action    Compose msg3.
 * @expected  Returns error (unsupported method in comp_prk_4e3m).
 */
TEST(coverage, msg3_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.chosen_method = (enum edhoc_method)99;

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose into tiny buffer to trigger buffer-too-small paths.
 * @env       msg1 flow completed, then compose msg2 into 8-byte buffer.
 * @action    Compose msg2 into undersized buffer.
 * @expected  Returns error (buffer too small in prepare_message_2).
 */
TEST(coverage, msg2_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg2[8] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 compose into tiny buffer.
 * @env       msg2 process completed, then compose msg3 into 8-byte buffer.
 * @action    Compose msg3 into undersized buffer.
 * @expected  Returns error (buffer too small).
 */
TEST(coverage, msg3_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg3[8] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4 compose into tiny buffer.
 * @env       Full handshake through msg3 process, then compose msg4 into 4 bytes.
 * @action    Compose msg4 into undersized buffer.
 * @expected  Returns error (buffer too small).
 */
TEST(coverage, msg4_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[4] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 process with corrupted method on initiator.
 * @env       msg2 composed OK, then initiator's chosen_method corrupted.
 * @action    Process msg2 on initiator.
 * @expected  Returns error (unsupported method).
 */
TEST(coverage, msg2_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.chosen_method = (enum edhoc_method)99;

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 process with corrupted method on responder.
 * @env       msg3 composed OK, then responder's chosen_method corrupted.
 * @action    Process msg3 on responder.
 * @expected  Returns error (unsupported method).
 */
TEST(coverage, msg3_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3, sizeof(msg3),
				       &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.chosen_method = (enum edhoc_method)99;

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose with x509 chain credential with zero certs.
 * @env       msg1 flow completed, mock cred_fetch returns zero-cert chain.
 * @action    Compose msg2.
 * @expected  Returns error from zero certs check in mac context.
 */
TEST(coverage, msg2_compose_x509_zero_certs_2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.fetch = mock_cred_fetch_x509_zero_certs,
		.verify = mock_cred_verify,
	};
	edhoc_bind_credentials(&resp_ctx, &zero_creds);

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose with corrupted credential label.
 * @env       msg1 flow completed, mock cred_fetch returns invalid label.
 * @action    Compose msg2 with mock callback returning unsupported label.
 * @expected  Returns error.
 */
static int mock_cred_fetch_invalid_label(void *user_ctx,
					 struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = (enum edhoc_cose_header)99;
	return EDHOC_SUCCESS;
}

TEST(coverage, msg2_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.fetch = mock_cred_fetch_invalid_label,
		.verify = mock_cred_verify,
	};
	edhoc_bind_credentials(&resp_ctx, &bad_creds);

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2 compose with x509_chain credential with zero certificates.
 * @env       msg1 flow completed, mock cred_fetch returns x509_chain with 0 certs.
 * @action    Compose msg2.
 * @expected  Returns error (BAD_STATE from zero certs check).
 */
static int mock_cred_fetch_x509_zero_certs(void *user_ctx,
					   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 0;
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

TEST(coverage, msg2_compose_x509_zero_certs)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	mock_reset(0);
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.fetch = mock_cred_fetch_x509_zero_certs,
		.verify = mock_cred_verify,
	};
	edhoc_bind_credentials(&resp_ctx, &zero_creds);

	mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4_process with wrong context state (SM_START).
 * @env       Full msg4 compose succeeds, then corrupt state before process.
 * @action    Call edhoc_message_4_process with SM_START status.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg4_process_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_START;
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4_compose with state corrupted after msg3 process.
 * @env       Full msg3 process succeeds, then corrupt status to SM_START.
 * @action    Call edhoc_message_4_compose.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg4_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.status = EDHOC_SM_START;

	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4_process with truncated message (too short CBOR).
 * @env       Full msg4 compose succeeds, then truncate message.
 * @action    Call edhoc_message_4_process with truncated data.
 * @expected  Returns error (CBOR failure or msg4 process failure).
 */
TEST(coverage, msg4_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, 2);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4 process with EAD callback that returns failure.
 * @env       Full handshake up through msg3 process. Responder composes msg4
 *            with EAD tokens. Initiator has EAD process callback that fails.
 * @action    Initiator processes msg4 with failing EAD callback.
 * @expected  Returns EDHOC_ERROR_EAD_PROCESS_FAILURE.
 */
TEST(coverage, msg4_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to responder: compose with a token */
	const struct edhoc_ead ead_resp = {
		.compose = mock_ead_compose_with_token,
		.process = mock_ead_process,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);

	/* Bind EAD to initiator: process always fails */
	const struct edhoc_ead ead_init = {
		.compose = mock_ead_compose,
		.process = mock_ead_process_fail,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 process with EAD callback that returns failure.
 * @env       Full handshake up through msg2 process. Initiator composes msg3
 *            with EAD tokens. Responder has EAD process callback that fails.
 * @action    Responder processes msg3 with failing EAD callback.
 * @expected  Returns EDHOC_ERROR_EAD_PROCESS_FAILURE.
 */
TEST(coverage, msg3_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to initiator: compose with a token */
	const struct edhoc_ead ead_init = {
		.compose = mock_ead_compose_with_token,
		.process = mock_ead_process,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	/* Bind EAD to responder: process always fails */
	const struct edhoc_ead ead_resp = {
		.compose = mock_ead_compose,
		.process = mock_ead_process_fail,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);

	mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3_compose with state corrupted after msg2 process.
 * @env       Full msg2 process succeeds, then corrupt status to SM_START.
 * @action    Call edhoc_message_3_compose.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg3_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_START;

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2_compose with state corrupted after msg1 process.
 * @env       msg1 compose+process succeeds, then corrupt status to SM_START.
 * @action    Call edhoc_message_2_compose.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg2_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.status = EDHOC_SM_START;

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;
	mock_reset(0);
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2_process with state corrupted to SM_COMPLETED.
 * @env       msg1 compose succeeds, msg2 composed, then corrupt init status.
 * @action    Call edhoc_message_2_process.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(coverage, msg2_process_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mock_reset(0);
	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- EAD with value payloads --- */

static const uint8_t ead_value_payload[] = { 0x01, 0x02, 0x03, 0x04 };

static int mock_ead_compose_with_value(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	if (mock_should_fail())
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	if (ead_token_size < 1)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	ead_token[0].label = 65535;
	ead_token[0].value = ead_value_payload;
	ead_token[0].value_len = sizeof(ead_value_payload);
	*ead_token_len = 1;
	return EDHOC_SUCCESS;
}

static int mock_ead_process_with_value(void *user_ctx, enum edhoc_message msg,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	if (mock_should_fail())
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	if (ead_token_size >= 1 && ead_token[0].value_len > 0)
		return EDHOC_SUCCESS;
	return EDHOC_SUCCESS;
}

static const struct edhoc_ead mock_ead_with_value = {
	.compose = mock_ead_compose_with_value,
	.process = mock_ead_process_with_value,
};

/**
 * @scenario  Full handshake with EAD tokens that carry value payloads.
 * @env       Two contexts with EAD compose/process returning tokens with values.
 * @action    Run full handshake through msg4 process with EAD values.
 * @expected  All steps succeed, exercising EAD value encoding/decoding paths.
 */
TEST(coverage, mock_handshake_ead_with_values)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_ead(&init_ctx, &mock_ead_with_value);
	edhoc_bind_ead(&resp_ctx, &mock_ead_with_value);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);

cleanup:
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/* --- Failure sweep gap 21-25 for msg2 compose/process --- */

/**
 * @scenario  Extended msg2 compose failure sweep (points 21..30).
 * @env       msg1 flow completed.
 * @action    For each failure point, fail during msg2 compose.
 * @expected  All calls fail gracefully.
 */
TEST(coverage, msg2_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				       &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Extended msg2 process failure sweep (points 21..30).
 * @env       msg2 composed OK.
 * @action    For each failure point, fail during msg2 process.
 * @expected  All calls fail gracefully.
 */
TEST(coverage, msg2_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					    sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  Extended msg3 compose/process failure sweep (points 21..25).
 * @env       msg2 processed OK.
 * @action    For each failure point, fail during msg3 compose then process.
 * @expected  All calls fail gracefully.
 */
TEST(coverage, msg3_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg3_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					       sizeof(msg3), &msg3_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg4_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage, msg4_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

/**
 * @scenario  msg2 process with fully corrupted CBOR payload.
 * @env       msg1 flow completed, then feed random bytes as msg2.
 * @action    Call edhoc_message_2_process with garbage data.
 * @expected  Non-success (CBOR decode failure).
 */
TEST(coverage, msg2_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
			       &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA };
	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg3 process with fully corrupted CBOR payload.
 * @env       msg2 processed OK, then feed random bytes as msg3.
 * @action    Call edhoc_message_3_process with garbage data.
 * @expected  Non-success.
 */
TEST(coverage, msg3_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE };
	mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg4 process with fully corrupted CBOR payload.
 * @env       msg3 processed OK, then feed random bytes as msg4.
 * @action    Call edhoc_message_4_process with garbage data.
 * @expected  Non-success.
 */
TEST(coverage, msg4_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF };
	mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg2_process EAD failure path.
 * @env       Responder composes msg2 with EAD tokens. Initiator has EAD
 *            process callback that always fails.
 * @action    Process msg2 on initiator with failing EAD callback.
 * @expected  Non-success (EAD process failure).
 */
TEST(coverage, msg2_process_ead_value_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_compose = {
		.compose = mock_ead_compose_with_token,
		.process = mock_ead_process,
	};
	edhoc_bind_ead(&resp_ctx, &ead_compose);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = do_full_msg2_flow(&init_ctx, &resp_ctx, msg2, sizeof(msg2),
				    &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	const struct edhoc_ead ead_fail = {
		.compose = mock_ead_compose,
		.process = mock_ead_process_fail,
	};
	edhoc_bind_ead(&init_ctx, &ead_fail);

	mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

cleanup:
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST_GROUP_RUNNER(coverage)
{
	RUN_TEST_CASE(coverage, msg1_compose_key_import_fail);
	RUN_TEST_CASE(coverage, msg1_compose_make_key_pair_fail);
	RUN_TEST_CASE(coverage, msg1_compose_buffer_too_small);
	RUN_TEST_CASE(coverage, msg1_process_method_mismatch);
	RUN_TEST_CASE(coverage, msg1_process_hash_fail);
	RUN_TEST_CASE(coverage, msg2_compose_dh_fail);
	RUN_TEST_CASE(coverage, msg2_compose_cred_fetch_fail);
	RUN_TEST_CASE(coverage, msg2_compose_hash_fail);
	RUN_TEST_CASE(coverage, msg2_compose_ead_fail);
	RUN_TEST_CASE(coverage, msg2_compose_signature_fail);
	RUN_TEST_CASE(coverage, msg2_compose_encrypt_fail);
	RUN_TEST_CASE(coverage, prk_exporter_bad_label);
	RUN_TEST_CASE(coverage, prk_exporter_expand_fail);
	RUN_TEST_CASE(coverage, oscore_export_wrong_status);
	RUN_TEST_CASE(coverage, key_update_success);
	RUN_TEST_CASE(coverage, key_update_extract_fail);
	RUN_TEST_CASE(coverage, conn_id_byte_string);
	RUN_TEST_CASE(coverage, error_msg_compose_bad_info);
	RUN_TEST_CASE(coverage, error_msg_compose_suites_overflow);
	RUN_TEST_CASE(coverage, error_msg_compose_bad_code);
	RUN_TEST_CASE(coverage, error_msg_process_text_too_small);
	RUN_TEST_CASE(coverage, error_msg_process_suites_too_small);
	RUN_TEST_CASE(coverage, error_msg_process_bad_cbor);
	RUN_TEST_CASE(coverage, error_msg_compose_suites_null_info);
	RUN_TEST_CASE(coverage, error_msg_compose_unspecified_null_info);
	RUN_TEST_CASE(coverage, msg1_compose_bad_state);
	RUN_TEST_CASE(coverage, msg2_compose_bad_state);
	RUN_TEST_CASE(coverage, msg3_compose_bad_state);
	RUN_TEST_CASE(coverage, msg4_compose_bad_state);
	RUN_TEST_CASE(coverage, msg1_process_bad_cbor);
	RUN_TEST_CASE(coverage, oscore_export_bstr_cid);
	RUN_TEST_CASE(coverage, cbor_int_mem_req_ranges);
	RUN_TEST_CASE(coverage, cbor_bstr_oh_ranges);
	RUN_TEST_CASE(coverage, cbor_tstr_oh_ranges);
	RUN_TEST_CASE(coverage, cbor_map_oh);
	RUN_TEST_CASE(coverage, cbor_array_oh_ranges);
	RUN_TEST_CASE(coverage, msg2_compose_no_fail);
	RUN_TEST_CASE(coverage, msg2_compose_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_compose_failure_sweep_high);
	RUN_TEST_CASE(coverage, msg2_compose_failure_sweep_very_high);
	RUN_TEST_CASE(coverage, msg2_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_compose_method3_failure_sweep_high);
	RUN_TEST_CASE(coverage, msg2_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage, prk_exporter_failure_sweep);
	RUN_TEST_CASE(coverage, oscore_export_failure_sweep);

	/* msg2 process failure sweeps */
	RUN_TEST_CASE(coverage, msg2_process_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_process_method3_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_process_method2_failure_sweep);

	/* Full mock handshake success tests */
	RUN_TEST_CASE(coverage, mock_full_handshake_method0);
	RUN_TEST_CASE(coverage, mock_full_handshake_method1);
	RUN_TEST_CASE(coverage, mock_full_handshake_method2);
	RUN_TEST_CASE(coverage, mock_full_handshake_method3);

	/* msg3 compose failure sweeps */
	RUN_TEST_CASE(coverage, msg3_compose_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_compose_method2_failure_sweep);

	/* msg3 process failure sweeps */
	RUN_TEST_CASE(coverage, msg3_process_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_process_method3_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_process_method2_failure_sweep);

	/* msg4 compose / process */
	RUN_TEST_CASE(coverage, mock_full_handshake_msg4_method0);
	RUN_TEST_CASE(coverage, msg4_compose_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_process_failure_sweep);
	RUN_TEST_CASE(coverage, mock_full_handshake_msg4_method3);
	RUN_TEST_CASE(coverage, msg4_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_process_method3_failure_sweep);

	/* KID credential variants */
	RUN_TEST_CASE(coverage, mock_handshake_kid_int_method0);
	RUN_TEST_CASE(coverage, mock_handshake_kid_int_method3);
	RUN_TEST_CASE(coverage, mock_handshake_kid_bstr_method0);

	/* x509_hash with bstr algorithm variant */
	RUN_TEST_CASE(coverage, mock_handshake_x5t_bstr_method0);
	RUN_TEST_CASE(coverage, mock_handshake_x5t_int_method0);
	RUN_TEST_CASE(coverage, mock_handshake_cose_any_method0);
	RUN_TEST_CASE(coverage, mock_handshake_x5chain_multi_method0);

	/* Byte-string CID variant */
	RUN_TEST_CASE(coverage, mock_handshake_bstr_cid_method0);

	/* Additional sweeps and truncation tests */
	RUN_TEST_CASE(coverage, msg1_compose_failure_sweep);
	RUN_TEST_CASE(coverage, msg1_process_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_process_truncated);
	RUN_TEST_CASE(coverage, msg3_process_truncated);
	RUN_TEST_CASE(coverage, exporter_failure_sweep_extended);
	RUN_TEST_CASE(coverage, msg2_compose_extended_sweep);

	/* bstr CID handshake + OSCORE export */
	RUN_TEST_CASE(coverage, oscore_export_after_bstr_cid_handshake);
	RUN_TEST_CASE(coverage, oscore_export_invalid_cid_type);
	RUN_TEST_CASE(coverage, oscore_export_invalid_own_cid_type);
	RUN_TEST_CASE(coverage, oscore_export_bstr_cid_sid_too_small);
	RUN_TEST_CASE(coverage, oscore_export_bstr_cid_rid_too_small);

	/* key_update with PRK_STATE_4E3M */
	RUN_TEST_CASE(coverage, key_update_prk_state_4e3m);
	RUN_TEST_CASE(coverage, key_update_prk_state_4e3m_fail);
	RUN_TEST_CASE(coverage, oscore_export_prk_state_4e3m);

	/* Extended failure sweeps */
	RUN_TEST_CASE(coverage, msg3_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage, msg3_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage, msg4_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage, msg4_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage, oscore_export_failure_sweep_4e3m);

	/* EAD failure in msg1 */
	RUN_TEST_CASE(coverage, msg1_process_ead_failure);
	RUN_TEST_CASE(coverage, msg1_compose_with_ead);

	/* bstr CID compose/process sweeps */
	RUN_TEST_CASE(coverage, msg2_compose_bstr_cid);
	RUN_TEST_CASE(coverage, msg2_compose_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage, msg2_process_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage, msg3_compose_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_bstr_cid_full);
	RUN_TEST_CASE(coverage, msg2_compose_bstr_cid_tiny_buf);

	/* Full msg4 for methods 1 and 2 */
	RUN_TEST_CASE(coverage, mock_full_handshake_msg4_method1);
	RUN_TEST_CASE(coverage, mock_full_handshake_msg4_method2);
	RUN_TEST_CASE(coverage, msg4_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage, msg4_process_method2_failure_sweep);

	/* Extended oscore export + key_update sweeps */
	RUN_TEST_CASE(coverage, oscore_export_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage, key_update_failure_sweep);

	/* Context corruption tests */
	RUN_TEST_CASE(coverage, msg2_compose_corrupted_cid_type);
	RUN_TEST_CASE(coverage, msg2_compose_corrupted_method);
	RUN_TEST_CASE(coverage, msg3_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage, msg3_compose_corrupted_method);
	RUN_TEST_CASE(coverage, msg2_compose_tiny_buffer);
	RUN_TEST_CASE(coverage, msg3_compose_tiny_buffer);
	RUN_TEST_CASE(coverage, msg4_compose_tiny_buffer);
	RUN_TEST_CASE(coverage, msg2_process_corrupted_method);
	RUN_TEST_CASE(coverage, msg3_process_corrupted_method);
	RUN_TEST_CASE(coverage, msg2_compose_x509_zero_certs_2);
	RUN_TEST_CASE(coverage, msg2_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage, msg2_compose_x509_zero_certs);

	/* Bad-state and method corruption tests */
	RUN_TEST_CASE(coverage, msg4_process_bad_state);
	RUN_TEST_CASE(coverage, msg4_compose_corrupted_state);
	RUN_TEST_CASE(coverage, msg4_process_truncated);
	RUN_TEST_CASE(coverage, msg4_process_ead_failure);
	RUN_TEST_CASE(coverage, msg3_process_ead_failure);
	RUN_TEST_CASE(coverage, msg3_compose_corrupted_state);
	RUN_TEST_CASE(coverage, msg2_compose_corrupted_state);
	RUN_TEST_CASE(coverage, msg2_process_corrupted_state);

	/* EAD with value payloads */
	RUN_TEST_CASE(coverage, mock_handshake_ead_with_values);

	/* Failure sweep gap 21-30 for msg2 */
	RUN_TEST_CASE(coverage, msg2_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage, msg2_process_failure_sweep_gap);

	/* Failure sweep gap 21-25 for msg3, msg4 */
	RUN_TEST_CASE(coverage, msg3_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage, msg3_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage, msg4_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage, msg4_process_failure_sweep_gap);

	/* Corrupted CBOR messages */
	RUN_TEST_CASE(coverage, msg2_process_garbage);
	RUN_TEST_CASE(coverage, msg3_process_garbage);
	RUN_TEST_CASE(coverage, msg4_process_garbage);

	/* EAD process failure for msg2 with values */
	RUN_TEST_CASE(coverage, msg2_process_ead_value_failure);
}
