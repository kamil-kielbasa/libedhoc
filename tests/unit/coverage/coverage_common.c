/**
 * \file    coverage_common.c
 * \author  Kamil Kielbasa
 * \brief   Shared mock infrastructure for coverage unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
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

/* Mock key callbacks */
static int mock_key_import(void *user_ctx, enum edhoc_key_type key_type,
			   const uint8_t *raw_key, size_t raw_key_len,
			   void *kid)
{
	(void)user_ctx;
	(void)key_type;
	(void)raw_key;
	(void)raw_key_len;
	if (coverage_mock_should_fail())
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

/*
 * The coverage tests bind the real cipher suite 2 descriptor (P-256 / SHA-256)
 * together with these mock crypto callbacks. Cipher suite 2 produces 32-byte
 * ECC keys, shared secrets, hashes and PRKs regardless of the context buffer
 * capacity (CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY / _MAC, which are sized for the
 * largest supported cipher suite). The mocks therefore report these fixed
 * suite-2 lengths so the core's length checks remain consistent.
 */
#define MOCK_SUITE2_ECC_KEY_LEN ((size_t)32)
#define MOCK_SUITE2_HASH_LEN ((size_t)32)

/* Mock crypto callbacks */
static int mock_make_key_pair(void *user_ctx, const void *kid,
			      uint8_t *priv_key, size_t priv_key_size,
			      size_t *priv_key_len, uint8_t *pub_key,
			      size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)kid;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(priv_key, 0xAA, priv_key_size);
	*priv_key_len = MOCK_SUITE2_ECC_KEY_LEN;
	memset(pub_key, 0xBB, pub_key_size);
	*pub_key_len = MOCK_SUITE2_ECC_KEY_LEN;
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
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(secret, 0xCC, secret_size);
	*secret_len = MOCK_SUITE2_ECC_KEY_LEN;
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
	if (coverage_mock_should_fail())
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
	if (coverage_mock_should_fail())
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
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(prk, 0xEE, prk_size);
	*prk_len = MOCK_SUITE2_HASH_LEN;
	return EDHOC_SUCCESS;
}

static int mock_expand(void *user_ctx, const void *kid, const uint8_t *info,
		       size_t info_len, uint8_t *okm, size_t okm_len)
{
	(void)user_ctx;
	(void)kid;
	(void)info;
	(void)info_len;
	if (coverage_mock_should_fail())
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
	if (coverage_mock_should_fail())
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

static int mock_hash(void *user_ctx, const uint8_t *input, size_t input_len,
		     uint8_t *hash, size_t hash_size, size_t *hash_len)
{
	(void)user_ctx;
	(void)input;
	(void)input_len;
	if (coverage_mock_should_fail())
		return EDHOC_ERROR_CRYPTO_FAILURE;
	memset(hash, 0x11, hash_size);
	*hash_len = MOCK_SUITE2_HASH_LEN;
	return EDHOC_SUCCESS;
}

/* Module interface variables and constants -------------------------------- */

const struct edhoc_keys coverage_mock_keys = {
	.import_key = mock_key_import,
	.destroy_key = mock_key_destroy,
};

const struct edhoc_crypto coverage_mock_crypto = {
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
void coverage_setup_mock_context(struct edhoc_context *ctx,
				 enum edhoc_method method)
{
	edhoc_context_init(ctx);

	const enum edhoc_method m[] = { method };
	edhoc_set_methods(ctx, m, 1);
	edhoc_set_cipher_suites(ctx, edhoc_cipher_suite_2_get_suite(), 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = -24,
	};
	edhoc_set_connection_id(ctx, &cid);

	edhoc_bind_keys(ctx, &coverage_mock_keys);
	edhoc_bind_crypto(ctx, &coverage_mock_crypto);
	edhoc_bind_credentials(ctx, &coverage_mock_creds);
	edhoc_bind_ead(ctx, &coverage_mock_ead);
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

void coverage_setup_mock_context_kid(struct edhoc_context *ctx,
				     enum edhoc_method method)
{
	coverage_setup_mock_context(ctx, method);
	edhoc_bind_credentials(ctx, &coverage_mock_creds_kid);
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
	static const uint8_t kid[] = { 0xAB };
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
	static const uint8_t alg[] = { 0x53, 0x48, 0x41 }; /* "SHA" */
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
void coverage_setup_mock_context_bstr_cid(struct edhoc_context *ctx,
					  enum edhoc_method method)
{
	coverage_setup_mock_context(ctx, method);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	edhoc_set_connection_id(ctx, &cid);
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
