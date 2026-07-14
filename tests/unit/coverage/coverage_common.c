/**
 * \file    coverage_common.c
 * \author  Kamil Kielbasa
 * \brief   Shared mock infrastructure for coverage unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
#include "test_platform.h"
#include "coverage_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/* Static variables and constants ------------------------------------------ */

static int mock_call_count;
static int mock_fail_at;

/* Module interface function definitions ----------------------------------- */

void coverage_mock_reset(int fail_at)
{
	mock_call_count = 0;
	mock_fail_at = fail_at;
}

bool coverage_mock_should_fail(void)
{
	mock_call_count++;
	return (mock_fail_at > 0 && mock_call_count >= mock_fail_at);
}

/* Static function definitions --------------------------------------------- */

/*
 * The coverage tests bind the real cipher suite 2 descriptor (P-256 / SHA-256)
 * together with these handle-only mock crypto callbacks. The mock never touches
 * PSA: OUT key handles get a fixed non-null placeholder (the core only tracks
 * slot liveness, never the handle value) and raw outputs are filled with a
 * constant. Cipher suite 2 produces 32-byte ECC keys, shared secrets, hashes
 * and PRKs, so the mocks report those fixed lengths.
 *
 * Failure injection counts the meaningful operations. destroy_key and the
 * multipart-hash bookkeeping (hash_init / hash_update / hash_abort) do NOT
 * increment the counter, so a full hash still costs one failure-injection step
 * (at hash_finish), matching the old single-shot hash callback.
 */
#define MOCK_SUITE2_ECC_KEY_LEN ((size_t)32)
#define MOCK_SUITE2_HASH_LEN ((size_t)32)

static void mock_set_handle(void *key_id)
{
	if (NULL != key_id)
		memset(key_id, 0x11, CONFIG_LIBEDHOC_KEY_ID_LEN);
}

static int mock_destroy_key(void *user_ctx, void *key_id)
{
	(void)user_ctx;
	(void)key_id;
	return EDHOC_SUCCESS;
}

static int mock_generate_key_pair(void *user_ctx, void *decaps_key_id,
				  uint8_t *encaps_key, size_t encaps_key_size,
				  size_t *encaps_key_len)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(decaps_key_id);
	memset(encaps_key, 0xBB, encaps_key_size);
	*encaps_key_len = MOCK_SUITE2_ECC_KEY_LEN;
	return EDHOC_SUCCESS;
}

static int mock_encapsulate(void *user_ctx, const uint8_t *encaps_key,
			    size_t encaps_key_len, void *decaps_key_id,
			    void *shared_secret_key_id, uint8_t *ciphertext,
			    size_t ciphertext_size, size_t *ciphertext_len)
{
	(void)user_ctx;
	(void)encaps_key;
	(void)encaps_key_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(decaps_key_id);
	mock_set_handle(shared_secret_key_id);
	memset(ciphertext, 0xCC, ciphertext_size);
	*ciphertext_len = MOCK_SUITE2_ECC_KEY_LEN;
	return EDHOC_SUCCESS;
}

static int mock_decapsulate(void *user_ctx, const void *decaps_key_id,
			    const uint8_t *ciphertext, size_t ciphertext_len,
			    void *shared_secret_key_id)
{
	(void)user_ctx;
	(void)decaps_key_id;
	(void)ciphertext;
	(void)ciphertext_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(shared_secret_key_id);
	return EDHOC_SUCCESS;
}

static int mock_key_agreement(void *user_ctx, const void *priv_key_id,
			      const uint8_t *peer_pub, size_t peer_pub_len,
			      void *shared_secret_key_id)
{
	(void)user_ctx;
	(void)priv_key_id;
	(void)peer_pub;
	(void)peer_pub_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(shared_secret_key_id);
	return EDHOC_SUCCESS;
}

static int mock_sign(void *user_ctx, const void *priv_key_id,
		     const uint8_t *input, size_t input_len, uint8_t *sign,
		     size_t sign_size, size_t *sign_len)
{
	(void)user_ctx;
	(void)priv_key_id;
	(void)input;
	(void)input_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(sign, 0xDD, sign_size);
	*sign_len = sign_size;
	return EDHOC_SUCCESS;
}

static int mock_verify(void *user_ctx, const uint8_t *pub_key,
		       size_t pub_key_len, const uint8_t *input,
		       size_t input_len, const uint8_t *sign, size_t sign_len)
{
	(void)user_ctx;
	(void)pub_key;
	(void)pub_key_len;
	(void)input;
	(void)input_len;
	(void)sign;
	(void)sign_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	return EDHOC_SUCCESS;
}

static int mock_extract(void *user_ctx, const void *ikm_key_id,
			const uint8_t *salt, size_t salt_len, void *prk_key_id)
{
	(void)user_ctx;
	(void)ikm_key_id;
	(void)salt;
	(void)salt_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(prk_key_id);
	return EDHOC_SUCCESS;
}

static int mock_expand(void *user_ctx, const void *prk_key_id,
		       const uint8_t *info, size_t info_len,
		       enum edhoc_key_usage usage, void *output_key_id)
{
	(void)user_ctx;
	(void)prk_key_id;
	(void)info;
	(void)info_len;
	(void)usage;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	mock_set_handle(output_key_id);
	return EDHOC_SUCCESS;
}

static int mock_expand_raw(void *user_ctx, const void *prk_key_id,
			   const uint8_t *info, size_t info_len,
			   uint8_t *output, size_t output_len)
{
	(void)user_ctx;
	(void)prk_key_id;
	(void)info;
	(void)info_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(output, 0xFF, output_len);
	return EDHOC_SUCCESS;
}

static int mock_aead_encrypt(void *user_ctx, const void *key_id,
			     const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len,
			     const uint8_t *ptxt, size_t ptxt_len,
			     uint8_t *ctxt, size_t ctxt_size, size_t *ctxt_len)
{
	(void)user_ctx;
	(void)key_id;
	(void)nonce;
	(void)nonce_len;
	(void)aad;
	(void)aad_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	if (ptxt && ptxt_len > 0)
		memcpy(ctxt, ptxt, ptxt_len);
	else
		memset(ctxt, 0, ctxt_size);
	*ctxt_len = ptxt_len + 8;
	return EDHOC_SUCCESS;
}

static int mock_aead_decrypt(void *user_ctx, const void *key_id,
			     const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len,
			     const uint8_t *ctxt, size_t ctxt_len,
			     uint8_t *ptxt, size_t ptxt_size, size_t *ptxt_len)
{
	(void)user_ctx;
	(void)key_id;
	(void)nonce;
	(void)nonce_len;
	(void)aad;
	(void)aad_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	size_t plen = ctxt_len > 8 ? ctxt_len - 8 : 0;
	if (plen > ptxt_size)
		plen = ptxt_size;
	if (ctxt && plen > 0)
		memcpy(ptxt, ctxt, plen);
	*ptxt_len = plen;
	return EDHOC_SUCCESS;
}

/* A single static token is a valid backend-owned multipart hash operation. */
static int mock_hash_op_token;

static int mock_hash_init(void *user_ctx, void **operation)
{
	(void)user_ctx;
	if (NULL == operation)
		return EDHOC_ERROR_INVALID_ARGUMENT;
	*operation = &mock_hash_op_token;
	return EDHOC_SUCCESS;
}

static int mock_hash_update(void *user_ctx, void *operation,
			    const uint8_t *input, size_t input_len)
{
	(void)user_ctx;
	(void)operation;
	(void)input;
	(void)input_len;
	return EDHOC_SUCCESS;
}

static int mock_hash_finish(void *user_ctx, void *operation, uint8_t *hash,
			    size_t hash_size, size_t *hash_len)
{
	(void)user_ctx;
	(void)operation;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(hash, 0x11, hash_size);
	*hash_len = MOCK_SUITE2_HASH_LEN;
	return EDHOC_SUCCESS;
}

static int mock_hash_abort(void *user_ctx, void *operation)
{
	(void)user_ctx;
	(void)operation;
	return EDHOC_SUCCESS;
}

/* Module interface variables and constants -------------------------------- */

const struct edhoc_crypto coverage_mock_crypto = {
	.destroy_key = mock_destroy_key,
	.generate_key_pair = mock_generate_key_pair,
	.encapsulate = mock_encapsulate,
	.decapsulate = mock_decapsulate,
	.key_agreement = mock_key_agreement,
	.sign = mock_sign,
	.verify = mock_verify,
	.extract = mock_extract,
	.expand = mock_expand,
	.expand_raw = mock_expand_raw,
	.aead_encrypt = mock_aead_encrypt,
	.aead_decrypt = mock_aead_decrypt,
	.hash_init = mock_hash_init,
	.hash_update = mock_hash_update,
	.hash_finish = mock_hash_finish,
	.hash_abort = mock_hash_abort,
};

/* Mock credential callbacks */
static int mock_cred_fetch(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;

	static const uint8_t fake_cert[] = { 0x30, 0x00 };
	auth_cred->x509_chain.cert[0] = fake_cert;
	auth_cred->x509_chain.cert_len[0] = sizeof(fake_cert);
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

int coverage_mock_cred_verify(void *user_ctx,
			      struct edhoc_auth_creds *auth_cred,
			      const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	static const uint8_t fake_pk[65] = { 0x04 };
	*pub_key = fake_pk;
	*pub_key_len = sizeof(fake_pk);
	return EDHOC_SUCCESS;
}

const struct edhoc_credentials coverage_mock_creds = {
	.fetch = mock_cred_fetch,
	.verify = coverage_mock_cred_verify,
};

int coverage_mock_ead_compose(void *user_ctx, enum edhoc_message msg,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	*ead_token_len = 0;
	return EDHOC_SUCCESS;
}

int coverage_mock_ead_process(void *user_ctx, enum edhoc_message msg,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	return EDHOC_SUCCESS;
}

const struct edhoc_ead coverage_mock_ead = {
	.compose = coverage_mock_ead_compose,
	.process = coverage_mock_ead_process,
};

/* Forward declarations for specialized mock callbacks */
int coverage_mock_cred_fetch_invalid_label(void *user_ctx,
					   struct edhoc_auth_creds *auth_cred);
int coverage_mock_cred_fetch_x509_zero_certs(
	void *user_ctx, struct edhoc_auth_creds *auth_cred);

/* Helper to set up a fully bound context with mocks */
int coverage_setup_mock_context(struct edhoc_context *ctx,
				enum edhoc_method method)
{
	int ret = edhoc_context_init(ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	const enum edhoc_method m[] = { method };
	ret = edhoc_set_methods(ctx, m, 1);
	if (EDHOC_SUCCESS != ret)
		return ret;

	ret = edhoc_set_cipher_suites(ctx, edhoc_cipher_suite_2_get_suite(), 1);
	if (EDHOC_SUCCESS != ret)
		return ret;

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = -24,
	};
	ret = edhoc_set_connection_id(ctx, &cid);
	if (EDHOC_SUCCESS != ret)
		return ret;

	ret = edhoc_bind_crypto(ctx, &coverage_mock_crypto);
	if (EDHOC_SUCCESS != ret)
		return ret;

	ret = edhoc_bind_platform(ctx, test_get_platform());
	if (EDHOC_SUCCESS != ret)
		return ret;

	ret = edhoc_bind_credentials(ctx, &coverage_mock_creds);
	if (EDHOC_SUCCESS != ret)
		return ret;

	return edhoc_bind_ead(ctx, &coverage_mock_ead);
}

int coverage_do_msg1_flow(struct edhoc_context *init_ctx,
			  struct edhoc_context *resp_ctx, uint8_t *msg1,
			  size_t msg1_size, size_t *msg1_len)
{
	coverage_mock_reset(0);
	int ret = edhoc_message_1_compose(init_ctx, msg1, msg1_size, msg1_len);
	if (EDHOC_SUCCESS != ret)
		return ret;
	coverage_mock_reset(0);
	return edhoc_message_1_process(resp_ctx, msg1, *msg1_len);
}

int coverage_do_full_msg2_flow(struct edhoc_context *init_ctx,
			       struct edhoc_context *resp_ctx, uint8_t *msg2,
			       size_t msg2_size, size_t *msg2_len)
{
	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	int ret = coverage_do_msg1_flow(init_ctx, resp_ctx, msg1, sizeof(msg1),
					&msg1_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	return edhoc_message_2_compose(resp_ctx, msg2, msg2_size, msg2_len);
}

int coverage_do_mock_msg2_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx)
{
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(init_ctx, resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	return edhoc_message_2_process(init_ctx, msg2, msg2_len);
}

int coverage_do_mock_msg3_compose(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx, uint8_t *msg3,
				  size_t msg3_size, size_t *msg3_len)
{
	int ret = coverage_do_mock_msg2_process(init_ctx, resp_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	return edhoc_message_3_compose(init_ctx, msg3, msg3_size, msg3_len);
}

int coverage_do_mock_msg3_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx)
{
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = coverage_do_mock_msg3_compose(init_ctx, resp_ctx, msg3,
						sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	return edhoc_message_3_process(resp_ctx, msg3, msg3_len);
}

int coverage_do_mock_msg4_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx)
{
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	int ret = coverage_do_mock_msg3_process(init_ctx, resp_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	ret = edhoc_message_4_compose(resp_ctx, msg4, sizeof(msg4), &msg4_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	coverage_mock_reset(0);
	return edhoc_message_4_process(init_ctx, msg4, msg4_len);
}

static int mock_cred_fetch_kid(void *user_ctx,
			       struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	auth_cred->key_id.key_id_int = 5;
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

const struct edhoc_credentials coverage_mock_creds_kid = {
	.fetch = mock_cred_fetch_kid,
	.verify = coverage_mock_cred_verify,
};

int coverage_setup_mock_context_kid(struct edhoc_context *ctx,
				    enum edhoc_method method)
{
	int ret = coverage_setup_mock_context(ctx, method);
	if (EDHOC_SUCCESS != ret)
		return ret;

	return edhoc_bind_credentials(ctx, &coverage_mock_creds_kid);
}

/* KID byte-string variant */
static int mock_cred_fetch_kid_bstr(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->key_id.cred_is_cbor = true;
	/* CBOR one-byte integer 5 — compact-encodable as ID_CRED. */
	static const uint8_t kid[] = { 0x05 };
	memcpy(auth_cred->key_id.key_id_bstr, kid, sizeof(kid));
	auth_cred->key_id.key_id_bstr_length = sizeof(kid);
	static const uint8_t fake_cred[] = { 0xA1, 0x01, 0x01 };
	auth_cred->key_id.cred = fake_cred;
	auth_cred->key_id.cred_len = sizeof(fake_cred);
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

const struct edhoc_credentials coverage_mock_creds_kid_bstr = {
	.fetch = mock_cred_fetch_kid_bstr,
	.verify = coverage_mock_cred_verify,
};

/* x509_hash with byte-string algorithm credential variant */
static int mock_cred_fetch_x5t_bstr(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_HASH;

	static const uint8_t fake_cert[] = { 0x30, 0x82, 0x01, 0x00 };
	auth_cred->x509_hash.cert = fake_cert;
	auth_cred->x509_hash.cert_len = sizeof(fake_cert);

	static const uint8_t fake_fp[] = { 0xAA, 0xBB, 0xCC, 0xDD };
	auth_cred->x509_hash.cert_fp = fake_fp;
	auth_cred->x509_hash.cert_fp_len = sizeof(fake_fp);

	auth_cred->x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	/* CBOR one-byte int for COSE_ALG_SHA_256_64 (-15). */
	static const uint8_t alg[] = { 0x2e };
	memcpy(auth_cred->x509_hash.alg_bstr, alg, sizeof(alg));
	auth_cred->x509_hash.alg_bstr_length = sizeof(alg);

	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

const struct edhoc_credentials coverage_mock_creds_x5t_bstr = {
	.fetch = mock_cred_fetch_x5t_bstr,
	.verify = coverage_mock_cred_verify,
};

/* x509_hash with integer algorithm credential variant */
static int mock_cred_fetch_x5t_int(void *user_ctx,
				   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
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

const struct edhoc_credentials coverage_mock_creds_x5t_int = {
	.fetch = mock_cred_fetch_x5t_int,
	.verify = coverage_mock_cred_verify,
};

/* x509_chain with multiple certificates */
static int mock_cred_fetch_x5chain_multi(void *user_ctx,
					 struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
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

const struct edhoc_credentials coverage_mock_creds_x5chain_multi = {
	.fetch = mock_cred_fetch_x5chain_multi,
	.verify = coverage_mock_cred_verify,
};

/* COSE_ANY credential variant with compact encoding */
static int mock_cred_fetch_cose_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
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

const struct edhoc_credentials coverage_mock_creds_cose_any = {
	.fetch = mock_cred_fetch_cose_any,
	.verify = coverage_mock_cred_verify,
};

/* Byte-string CID variant */
int coverage_setup_mock_context_bstr_cid(struct edhoc_context *ctx,
					 enum edhoc_method method)
{
	int ret = coverage_setup_mock_context(ctx, method);
	if (EDHOC_SUCCESS != ret)
		return ret;

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	return edhoc_set_connection_id(ctx, &cid);
}

int coverage_mock_ead_compose_with_token(void *user_ctx, enum edhoc_message msg,
					 struct edhoc_ead_token *ead_token,
					 size_t ead_token_size,
					 size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	if (coverage_mock_should_fail())
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

int coverage_mock_ead_process_fail(void *user_ctx, enum edhoc_message msg,
				   const struct edhoc_ead_token *ead_token,
				   size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;
	return EDHOC_ERROR_EAD_PROCESS_FAILURE;
}

int coverage_mock_cred_fetch_invalid_label(void *user_ctx,
					   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = (enum edhoc_cose_header)99;
	return EDHOC_SUCCESS;
}

int coverage_mock_cred_fetch_x509_zero_certs(void *user_ctx,
					     struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 0;
	memset(auth_cred->priv_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return EDHOC_SUCCESS;
}

static const uint8_t ead_value_payload[] = { 0x01, 0x02, 0x03, 0x04 };

int coverage_mock_ead_compose_with_value(void *user_ctx, enum edhoc_message msg,
					 struct edhoc_ead_token *ead_token,
					 size_t ead_token_size,
					 size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	if (ead_token_size < 1)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	ead_token[0].label = 65535;
	ead_token[0].value = ead_value_payload;
	ead_token[0].value_len = sizeof(ead_value_payload);
	*ead_token_len = 1;
	return EDHOC_SUCCESS;
}

int coverage_mock_ead_process_with_value(void *user_ctx, enum edhoc_message msg,
					 const struct edhoc_ead_token *ead_token,
					 size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	if (ead_token_size >= 1 && ead_token[0].value_len > 0)
		return EDHOC_SUCCESS;
	return EDHOC_SUCCESS;
}

const struct edhoc_ead coverage_mock_ead_with_value = {
	.compose = coverage_mock_ead_compose_with_value,
	.process = coverage_mock_ead_process_with_value,
};
