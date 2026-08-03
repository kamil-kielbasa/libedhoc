/**
 * \file    test_exporters.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for EDHOC exporter and error getter API functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/** PRK and transcript-hash length for cipher suite 2 (SHA-256). */
#define EXPORTERS_SHA256_LEN ((size_t)32)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/** \brief Non-elidable memory wipe for the bound test platform. */
static void exporters_platform_zeroize(void *buffer, size_t length);

/** \brief Import raw keying material as an HKDF DERIVE key handle. */
static void import_derive_ref(const uint8_t *key, size_t key_len,
			      uint8_t *out_key_id);

/** \brief Expand fixed info from a DERIVE key handle into \p out. */
static void expand_raw_probe(const uint8_t *key_id, uint8_t *out,
			     size_t out_len);

/** \brief Import raw keying material as an AEAD key mirroring \p like_key_id. */
static void import_aead_ref(const uint8_t *like_key_id, const uint8_t *key,
			    size_t key_len, uint8_t *out_key_id);

/** \brief Encrypt a fixed vector with an AEAD key handle; return ctxt length. */
static size_t aead_probe(const uint8_t *key_id, uint8_t *out, size_t out_size);

/** \brief Publish a raw PRK_4e3m as a key-store handle (no handshake). */
static void inject_prk_4e3m(struct edhoc_context *ctx, const uint8_t *prk,
			    size_t prk_len);

/** \brief Init a suite-2 context bound to the crypto vtable and platform. */
static void setup_basic_context(struct edhoc_context *ctx);

/** \brief Bring a context to a completed handshake ready for exporting. */
static void setup_export_ready(struct edhoc_context *ctx);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_crypto *crypto;

static const struct edhoc_platform exporters_platform = {
	.zeroize = exporters_platform_zeroize,
};

/* Static function definitions --------------------------------------------- */

static void exporters_platform_zeroize(void *buffer, size_t length)
{
	(void)memset(buffer, 0, length);
}

static void import_derive_ref(const uint8_t *key, size_t key_len,
			      uint8_t *out_key_id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, key, key_len, &kid);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	memcpy(out_key_id, &kid, sizeof(kid));
}

static void expand_raw_probe(const uint8_t *key_id, uint8_t *out,
			     size_t out_len)
{
	static const uint8_t info[] = { 0x01, 0x02, 0x03, 0x04 };

	const int ret = crypto->expand_raw(NULL, key_id, info, sizeof(info),
					   out, out_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

static void import_aead_ref(const uint8_t *like_key_id, const uint8_t *key,
			    size_t key_len, uint8_t *out_key_id)
{
	psa_key_id_t like = PSA_KEY_ID_NULL;

	memcpy(&like, like_key_id, sizeof(like));

	psa_key_attributes_t src = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(like, &src);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, psa_get_key_type(&src));
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, psa_get_key_algorithm(&src));
	psa_reset_key_attributes(&src);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	status = psa_import_key(&attr, key, key_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	memcpy(out_key_id, &kid, sizeof(kid));
}

static size_t aead_probe(const uint8_t *key_id, uint8_t *out, size_t out_size)
{
	/* The crypto vtable AEAD requires non-empty associated data. */
	static const uint8_t aad[] = { 'a', 'e', 'a', 'd', '-',
				       'p', 'r', 'o', 'b', 'e' };
	static const uint8_t pt[16] = { 0 };

	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2);

	TEST_ASSERT_NOT_NULL(params);

	uint8_t nonce[16] = { 0 };
	const size_t nonce_len = params->aead_iv_length;

	TEST_ASSERT_NOT_EQUAL(0, nonce_len);
	TEST_ASSERT_TRUE(nonce_len <= sizeof(nonce));

	size_t out_len = 0;
	const int ret = crypto->aead_encrypt(NULL, key_id, nonce, nonce_len,
					     aad, sizeof(aad), pt, sizeof(pt),
					     out, out_size, &out_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	return out_len;
}

static void inject_prk_4e3m(struct edhoc_context *ctx, const uint8_t *prk,
			    size_t prk_len)
{
	struct edhoc_key_slot *slot = &ctx->key_slots[EDHOC_KEY_SLOT_PRK_4E3M];

	import_derive_ref(prk, prk_len, slot->key_id);
	slot->present = true;
}

static void setup_basic_context(struct edhoc_context *ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	const uint8_t cid_value[] = { 0x01 };
	const struct edhoc_buffer cid = {
		.value = cid_value,
		.length = ARRAY_SIZE(cid_value),
	};

	memset(ctx, 0, sizeof(*ctx));

	int ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(
		ctx, edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(ctx, crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, &exporters_platform);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

static void setup_export_ready(struct edhoc_context *ctx)
{
	uint8_t prk[EXPORTERS_SHA256_LEN] = { 0 };

	setup_basic_context(ctx);

	ctx->state.role = EDHOC_ROLE_RESPONDER;
	ctx->state.machine = EDHOC_SM_COMPLETED;
	ctx->is_oscore_export_allowed = true;
	ctx->state.th.stage = EDHOC_TH_STATE_4;
	ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;

	memset(ctx->state.th.value, 0xAB, EXPORTERS_SHA256_LEN);
	ctx->state.th.length = EXPORTERS_SHA256_LEN;

	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(ctx, prk, sizeof(prk));

	ctx->negotiation.peer_connection_id.value[0] = 0x01;
	ctx->negotiation.peer_connection_id.length = 1;
	ctx->negotiation.connection_id.value[0] = 0x02;
	ctx->negotiation.connection_id.length = 1;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(exporters);

TEST_SETUP(exporters)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	crypto = edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2);
	TEST_ASSERT_NOT_NULL(crypto);
}

TEST_TEAR_DOWN(exporters)
{
	mbedtls_psa_crypto_free();
}

TEST(exporters, export_kdf_handle_matches_raw)
{
	struct edhoc_context ctx = { 0 };
	uint8_t raw[EXPORTERS_SHA256_LEN] = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t raw_ref[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t out_handle[16] = { 0 };
	uint8_t out_raw[16] = { 0 };

	setup_export_ready(&ctx);

	/* Raw bytes and a KDF key handle for the same label must agree. */
	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, raw, sizeof(raw));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 0,
			   EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The handle is a DERIVE key holding exactly the raw bytes: expanding
	 * from both with identical info yields identical output. */
	import_derive_ref(raw, sizeof(raw), raw_ref);
	expand_raw_probe(key_id, out_handle, sizeof(out_handle));
	expand_raw_probe(raw_ref, out_raw, sizeof(out_raw));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_raw, out_handle, sizeof(out_raw));

	ret = crypto->destroy_key(NULL, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, raw_ref);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_aead_handle_is_aes_128)
{
	struct edhoc_context ctx = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	setup_export_ready(&ctx);

	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_AEAD, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The AEAD handle is a real 128-bit AES key owned by the caller. */
	psa_key_id_t psa_kid = PSA_KEY_ID_NULL;

	memcpy(&psa_kid, key_id, sizeof(psa_kid));

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	const psa_status_t status = psa_get_key_attributes(psa_kid, &attr);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
	TEST_ASSERT_EQUAL(PSA_KEY_TYPE_AES, psa_get_key_type(&attr));
	TEST_ASSERT_EQUAL(128, psa_get_key_bits(&attr));
	psa_reset_key_attributes(&attr);

	ret = crypto->destroy_key(NULL, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_rejects_equal_connection_ids)
{
	struct edhoc_context ctx = { 0 };

	uint8_t master_secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;
	uint8_t out[32] = { 0 };

	setup_export_ready(&ctx);

	/* RFC 9528: 3.3.3 - C_I and C_R become the OSCORE Recipient IDs, so
	 * equal ones give both peers the same key and the same nonce. */
	ctx.negotiation.peer_connection_id.value[0] =
		ctx.negotiation.connection_id.value[0];

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), salt, sizeof(salt),
		sid, sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	/* The rejection must not consume the export permission. */
	TEST_ASSERT_TRUE(ctx.is_oscore_export_allowed);

	uint8_t master_secret_kid[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	ret = edhoc_export_oscore_context(&ctx, master_secret_kid, salt,
					  sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	/* The requirement comes from OSCORE, so plain exporting still works. */
	ret = edhoc_export_raw(&ctx, 32769, NULL, 0, out, sizeof(out));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_rejects_two_empty_connection_ids)
{
	struct edhoc_context ctx = { 0 };

	uint8_t master_secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	setup_export_ready(&ctx);

	ctx.negotiation.connection_id.length = 0;
	ctx.negotiation.peer_connection_id.length = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), salt, sizeof(salt),
		sid, sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_handle_matches_raw)
{
	struct edhoc_context ctx_raw = { 0 };
	struct edhoc_context ctx_handle = { 0 };
	uint8_t ms_raw[16] = { 0 };
	uint8_t salt_raw[8] = { 0 };
	uint8_t sid_raw[8] = { 0 };
	uint8_t rid_raw[8] = { 0 };
	size_t sid_raw_len = 0;
	size_t rid_raw_len = 0;

	uint8_t ms_kid[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t salt_h[8] = { 0 };
	uint8_t sid_h[8] = { 0 };
	uint8_t rid_h[8] = { 0 };
	size_t sid_h_len = 0;
	size_t rid_h_len = 0;

	uint8_t ms_ref[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	uint8_t out_h[32] = { 0 };
	uint8_t out_r[32] = { 0 };

	setup_export_ready(&ctx_raw);
	setup_export_ready(&ctx_handle);

	/* The OSCORE master secret has the application AEAD key length. */
	const size_t ms_len =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2)
			->aead_key_length;

	TEST_ASSERT_NOT_EQUAL(0, ms_len);
	TEST_ASSERT_TRUE(ms_len <= sizeof(ms_raw));

	/* One context exports fully raw, the other with the master secret as an
	 * AEAD key handle. Salt/IDs must match and the handle must hold exactly
	 * the raw master secret. */
	int ret = edhoc_export_oscore_context_raw(
		&ctx_raw, ms_raw, ms_len, salt_raw, sizeof(salt_raw), sid_raw,
		sizeof(sid_raw), &sid_raw_len, rid_raw, sizeof(rid_raw),
		&rid_raw_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_oscore_context(&ctx_handle, ms_kid, salt_h,
					  sizeof(salt_h), sid_h, sizeof(sid_h),
					  &sid_h_len, rid_h, sizeof(rid_h),
					  &rid_h_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(sid_raw_len, sid_h_len);
	TEST_ASSERT_EQUAL(rid_raw_len, rid_h_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(salt_raw, salt_h, sizeof(salt_raw));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(sid_raw, sid_h, sid_raw_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rid_raw, rid_h, rid_raw_len);

	/* The handle is an AEAD key: import the raw bytes as a matching key and
	 * compare by encrypting a fixed vector with each. */
	import_aead_ref(ms_kid, ms_raw, ms_len, ms_ref);

	const size_t out_h_len = aead_probe(ms_kid, out_h, sizeof(out_h));
	const size_t out_r_len = aead_probe(ms_ref, out_r, sizeof(out_r));

	TEST_ASSERT_EQUAL(out_h_len, out_r_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_h, out_r, out_h_len);

	ret = crypto->destroy_key(NULL, ms_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, ms_ref);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx_raw);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx_handle);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_null_ctx)
{
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	const int ret = edhoc_export(NULL, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				     NULL, 0, EDHOC_KEY_USAGE_KDF, key_id);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(exporters, export_null_key_id)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 0,
			   EDHOC_KEY_USAGE_KDF, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_context_null_with_nonzero_length)
{
	struct edhoc_context ctx = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 8,
			   EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_invalid_label)
{
	struct edhoc_context ctx = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	int ret = edhoc_export(&ctx, 100, NULL, 0, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_invalid_usage)
{
	struct edhoc_context ctx = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, (enum edhoc_key_usage)99, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_bad_state)
{
	struct edhoc_context ctx = { 0 };
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_raw_null_secret)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_raw_zero_length)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t secret[EXPORTERS_SHA256_LEN] = { 0 };
	ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, secret, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_raw_invalid_label)
{
	struct edhoc_context ctx = { 0 };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t secret[EXPORTERS_SHA256_LEN] = { 0 };
	int ret = edhoc_export_raw(&ctx, 100, NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, export_raw_bad_state)
{
	struct edhoc_context ctx = { 0 };
	uint8_t secret[EXPORTERS_SHA256_LEN] = { 0 };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_null_master_secret_key_id)
{
	struct edhoc_context ctx = { 0 };

	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	const int ret = edhoc_export_oscore_context(&ctx, NULL, salt,
						    sizeof(salt), sid,
						    sizeof(sid), &sid_len, rid,
						    sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(exporters, oscore_context_raw_not_allowed)
{
	struct edhoc_context ctx = { 0 };

	uint8_t ms[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = false;

	int ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_raw_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_WAIT_M2;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.is_oscore_export_allowed = true;

	int ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_raw_sender_id_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };

	uint8_t prk[EXPORTERS_SHA256_LEN] = { 0 };
	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[1] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	setup_basic_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	memset(ctx.state.th.value, 0xAB, EXPORTERS_SHA256_LEN);
	ctx.state.th.length = EXPORTERS_SHA256_LEN;

	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(&ctx, prk, sizeof(prk));

	/* A two byte identifier does not fit the one byte output buffer. */
	ctx.negotiation.peer_connection_id.value[0] = 0xaa;
	ctx.negotiation.peer_connection_id.value[1] = 0xbb;
	ctx.negotiation.peer_connection_id.length = 2;
	ctx.negotiation.connection_id.value[0] = 0x01;
	ctx.negotiation.connection_id.length = 1;

	int ret = edhoc_export_oscore_context_raw(&ctx, secret, sizeof(secret),
						  salt, sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, oscore_context_raw_recipient_id_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	uint8_t prk[EXPORTERS_SHA256_LEN] = { 0 };
	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[1] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	setup_basic_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	memset(ctx.state.th.value, 0xAB, EXPORTERS_SHA256_LEN);
	ctx.state.th.length = EXPORTERS_SHA256_LEN;

	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(&ctx, prk, sizeof(prk));

	/* A two byte identifier does not fit the one byte output buffer. */
	ctx.negotiation.peer_connection_id.value[0] = 0x01;
	ctx.negotiation.peer_connection_id.length = 1;
	ctx.negotiation.connection_id.value[0] = 0xaa;
	ctx.negotiation.connection_id.value[1] = 0xbb;
	ctx.negotiation.connection_id.length = 2;

	int ret = edhoc_export_oscore_context_raw(&ctx, secret, sizeof(secret),
						  salt, sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, key_update_null_context)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_key_update(&ctx, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, key_update_zero_context_length)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t context[EXPORTERS_SHA256_LEN] = { 0 };
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_key_update(&ctx, context, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(exporters, key_update_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t context[EXPORTERS_SHA256_LEN] = { 0xAA };

	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = edhoc_export_key_update(&ctx, context, sizeof(context));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(exporters)
{
	/* Positive paths. */
	RUN_TEST_CASE(exporters, export_kdf_handle_matches_raw);
	RUN_TEST_CASE(exporters, export_aead_handle_is_aes_128);
	RUN_TEST_CASE(exporters, oscore_context_rejects_equal_connection_ids);
	RUN_TEST_CASE(exporters,
		      oscore_context_rejects_two_empty_connection_ids);
	RUN_TEST_CASE(exporters, oscore_context_handle_matches_raw);

	/* Negative paths — edhoc_export / edhoc_export_raw. */
	RUN_TEST_CASE(exporters, export_null_ctx);
	RUN_TEST_CASE(exporters, export_null_key_id);
	RUN_TEST_CASE(exporters, export_context_null_with_nonzero_length);
	RUN_TEST_CASE(exporters, export_invalid_label);
	RUN_TEST_CASE(exporters, export_invalid_usage);
	RUN_TEST_CASE(exporters, export_bad_state);
	RUN_TEST_CASE(exporters, export_raw_null_secret);
	RUN_TEST_CASE(exporters, export_raw_zero_length);
	RUN_TEST_CASE(exporters, export_raw_invalid_label);
	RUN_TEST_CASE(exporters, export_raw_bad_state);

	/* Negative paths — edhoc_export_oscore_context / _raw. */
	RUN_TEST_CASE(exporters, oscore_context_null_master_secret_key_id);
	RUN_TEST_CASE(exporters, oscore_context_raw_not_allowed);
	RUN_TEST_CASE(exporters, oscore_context_raw_bad_state_not_completed);
	RUN_TEST_CASE(exporters, oscore_context_raw_sender_id_buffer_too_small);
	RUN_TEST_CASE(exporters,
		      oscore_context_raw_recipient_id_buffer_too_small);

	/* Negative paths — edhoc_export_key_update. */
	RUN_TEST_CASE(exporters, key_update_null_context);
	RUN_TEST_CASE(exporters, key_update_zero_context_length);
	RUN_TEST_CASE(exporters, key_update_bad_state_not_completed);
}
