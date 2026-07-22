/**
 * \file    test_exporters.c
 * \author  Kamil Kielbasa
 * \brief   Tests for EDHOC exporter and error getter API functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "test_platform.h"
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include <edhoc/edhoc.h>

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_crypto *crypto;

/* Static function definitions --------------------------------------------- */

/*
 * Import raw keying material as an HKDF DERIVE key and return the caller-owned
 * key handle. The exporter's PRKs use exactly these attributes, so an imported
 * reference can be compared against a library-derived key via expand_raw.
 */
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
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, key, key_len, &kid));
	memcpy(out_key_id, &kid, sizeof(kid));
}

/*
 * Expand raw output from a DERIVE key handle with fixed info. Two keys holding
 * the same bytes yield identical output, so this probes a non-exportable
 * handle for byte-equality against a known reference.
 */
static void expand_raw_probe(const uint8_t *key_id, uint8_t *out,
			     size_t out_len)
{
	static const uint8_t info[] = { 0x01, 0x02, 0x03, 0x04 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->expand_raw(NULL, key_id, info, sizeof(info),
					     out, out_len));
}

/*
 * Import raw keying material as an AEAD key mirroring an existing handle's type
 * and algorithm, so both can be probed for byte-equality by encryption.
 */
static void import_aead_ref(const uint8_t *like_key_id, const uint8_t *key,
			    size_t key_len, uint8_t *out_key_id)
{
	psa_key_id_t like = PSA_KEY_ID_NULL;
	memcpy(&like, like_key_id, sizeof(like));

	psa_key_attributes_t src = PSA_KEY_ATTRIBUTES_INIT;
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_get_key_attributes(like, &src));

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, psa_get_key_type(&src));
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, psa_get_key_algorithm(&src));
	psa_reset_key_attributes(&src);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, key, key_len, &kid));
	memcpy(out_key_id, &kid, sizeof(kid));
}

/*
 * Encrypt a fixed vector with an AEAD key handle through the crypto vtable
 * (aead_encrypt). Two keys holding the same bytes yield identical ciphertext,
 * so this probes a non-exportable AEAD handle for byte-equality against a known
 * reference.
 */
static size_t aead_probe(const uint8_t *key_id, uint8_t *out, size_t out_size)
{
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0);
	TEST_ASSERT_NOT_NULL(params);

	uint8_t nonce[16] = { 0 };
	const size_t nonce_len = params->aead_iv_length;
	TEST_ASSERT_NOT_EQUAL(0, nonce_len);
	TEST_ASSERT_TRUE(nonce_len <= sizeof(nonce));

	/* The crypto vtable AEAD requires non-empty associated data. */
	static const uint8_t aad[] = { 'a', 'e', 'a', 'd', '-',
				       'p', 'r', 'o', 'b', 'e' };
	static const uint8_t pt[16] = { 0 };
	size_t out_len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->aead_encrypt(NULL, key_id, nonce, nonce_len,
					       aad, sizeof(aad), pt, sizeof(pt),
					       out, out_size, &out_len));
	return out_len;
}

/*
 * The exporter tests inject a known PRK_4e3m without running a handshake. Under
 * the handle-only crypto interface the PRK is a key-store handle, so import the
 * raw material as a DERIVE key and publish the handle in the PRK_4e3m slot.
 */
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
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	memset(ctx, 0, sizeof(*ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_init(ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_set_methods(ctx, method, 1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_set_cipher_suites(
				  ctx, edhoc_cipher_suite_0_get_suite(), 1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_set_connection_id(ctx, &cid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_bind_crypto(ctx, crypto));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_platform(ctx, test_get_platform()));
}

/*
 * Put a context into a state where the exporter can run: a completed handshake
 * with PRK_4e3m present and short one-byte OSCORE connection identifiers.
 */
static void setup_export_ready(struct edhoc_context *ctx)
{
	setup_basic_context(ctx);
	ctx->state.role = EDHOC_ROLE_RESPONDER;
	ctx->state.machine = EDHOC_SM_COMPLETED;
	ctx->is_oscore_export_allowed = true;
	ctx->state.th.stage = EDHOC_TH_STATE_4;
	ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx->state.th.value, 0xAB, 32);
	ctx->state.th.length = 32;

	uint8_t prk[32];
	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(ctx, prk, sizeof(prk));

	ctx->negotiation.peer_connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx->negotiation.peer_connection_id.int_value = 1;
	ctx->negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx->negotiation.connection_id.int_value = 2;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(exporters);

TEST_SETUP(exporters)
{
	psa_crypto_init();
	crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(exporters)
{
	mbedtls_psa_crypto_free();
}

/* -- edhoc_error_get_code tests -- */

TEST(exporters, error_get_code_success_default)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	enum edhoc_error_code code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, code);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, error_get_code_after_set)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, code);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_error_get_cipher_suites tests -- */

TEST(exporters, error_get_cipher_suites_success)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.negotiation.cipher_suite.count = 2;
	ctx.negotiation.cipher_suite.entry[0].value = 0;
	ctx.negotiation.cipher_suite.entry[1].value = 2;
	ctx.negotiation.peer_cipher_suite.count = 1;
	ctx.negotiation.peer_cipher_suite.entry[0].value = 3;

	int32_t cs[3] = { -1, -1, -1 };
	int32_t peer_cs[3] = { -1, -1, -1 };
	size_t cs_len = 0;
	size_t peer_cs_len = 0;

	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, cs_len);
	TEST_ASSERT_EQUAL(0, cs[0]);
	TEST_ASSERT_EQUAL(2, cs[1]);
	TEST_ASSERT_EQUAL(1, peer_cs_len);
	TEST_ASSERT_EQUAL(3, peer_cs[0]);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, error_get_cipher_suites_peer_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.negotiation.cipher_suite.count = 1;
	ctx.negotiation.cipher_suite.entry[0].value = 0;
	ctx.negotiation.peer_cipher_suite.count = 3;

	int32_t cs[3];
	int32_t peer_cs[1];
	size_t cs_len = 0;
	size_t peer_cs_len = 0;

	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						1, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_key_update error paths -- */

TEST(exporters, key_update_null_entropy)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_export_key_update(&ctx, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, key_update_zero_entropy_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const uint8_t entropy[32] = { 0 };
	int ret = edhoc_export_key_update(&ctx, entropy, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, key_update_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	const uint8_t entropy[32] = { 0xAA };
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_oscore_session error paths -- */

TEST(exporters, oscore_session_raw_not_allowed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = false;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session_raw(&ctx, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, oscore_session_raw_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_WAIT_M2;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.is_oscore_export_allowed = true;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session_raw(&ctx, ms, sizeof(ms), salt,
						  sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_raw error paths -- */

TEST(exporters, export_raw_null_secret)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_raw_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	uint8_t secret[32];
	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, secret, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_raw_invalid_label)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t secret[32];
	int ret = edhoc_export_raw(&ctx, 100, NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_raw_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t secret[32];
	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, oscore_session_raw_sender_id_encode_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.state.th.value, 0xAB, 32);
	ctx.state.th.length = 32;

	uint8_t prk[32] = { 0 };
	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(&ctx, prk, sizeof(prk));

	ctx.negotiation.peer_connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.peer_connection_id.int_value = 24;

	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 1;

	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[1] = { 0 };
	size_t sid_len = 0;
	uint8_t rid[8] = { 0 };
	size_t rid_len = 0;

	int ret = edhoc_export_oscore_session_raw(&ctx, secret, sizeof(secret),
						  salt, sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, oscore_session_raw_recipient_id_encode_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.state.th.value, 0xAB, 32);
	ctx.state.th.length = 32;

	uint8_t prk[32] = { 0 };
	memset(prk, 0xCD, sizeof(prk));
	inject_prk_4e3m(&ctx, prk, sizeof(prk));

	ctx.negotiation.peer_connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.peer_connection_id.int_value = 1;

	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 24;

	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	size_t sid_len = 0;
	uint8_t rid[1] = { 0 };
	size_t rid_len = 0;

	int ret = edhoc_export_oscore_session_raw(&ctx, secret, sizeof(secret),
						  salt, sizeof(salt), sid,
						  sizeof(sid), &sid_len, rid,
						  sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export (key handle) tests -- */

TEST(exporters, export_null_ctx)
{
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(NULL, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(exporters, export_null_key_id)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_KDF, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_context_null_nonzero_len)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       8, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_invalid_label)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(&ctx, 100, NULL, 0, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_invalid_usage)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, (enum edhoc_key_usage)99, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.state.machine = EDHOC_SM_START;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_kdf_handle_matches_raw)
{
	struct edhoc_context ctx = { 0 };
	setup_export_ready(&ctx);

	/* Raw bytes and a KDF key handle for the same label must agree. */
	uint8_t raw[32] = { 0 };
	int ret = edhoc_export_raw(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET,
				   NULL, 0, raw, sizeof(raw));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 0,
			   EDHOC_KEY_USAGE_KDF, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The handle is a DERIVE key holding exactly the raw bytes: expanding
	 * from both with identical info yields identical output. */
	uint8_t raw_ref[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	import_derive_ref(raw, sizeof(raw), raw_ref);

	uint8_t out_handle[16] = { 0 };
	uint8_t out_raw[16] = { 0 };
	expand_raw_probe(key_id, out_handle, sizeof(out_handle));
	expand_raw_probe(raw_ref, out_raw, sizeof(out_raw));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_raw, out_handle, sizeof(out_raw));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, key_id));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, raw_ref));

	edhoc_context_deinit(&ctx);
}

TEST(exporters, export_aead_handle_success)
{
	struct edhoc_context ctx = { 0 };
	setup_export_ready(&ctx);

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_export(&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
			       0, EDHOC_KEY_USAGE_AEAD, key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The AEAD handle is a real 128-bit AES key owned by the caller. */
	psa_key_id_t psa_kid = PSA_KEY_ID_NULL;
	memcpy(&psa_kid, key_id, sizeof(psa_kid));
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_get_key_attributes(psa_kid, &attr));
	TEST_ASSERT_EQUAL(PSA_KEY_TYPE_AES, psa_get_key_type(&attr));
	TEST_ASSERT_EQUAL(128, psa_get_key_bits(&attr));
	psa_reset_key_attributes(&attr);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, key_id));

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_oscore_session (master secret handle) tests -- */

TEST(exporters, oscore_session_null_master_secret_key_id)
{
	struct edhoc_context ctx = { 0 };
	uint8_t salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(&ctx, NULL, salt, sizeof(salt),
					      sid, sizeof(sid), &sid_len, rid,
					      sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(exporters, oscore_session_handle_matches_raw)
{
	/* Two identical contexts export the OSCORE session: one fully raw, one
	 * with the master secret as an AEAD key handle. Salt/IDs must match and
	 * the handle must hold exactly the raw master secret. */
	struct edhoc_context ctx_raw = { 0 };
	struct edhoc_context ctx_handle = { 0 };
	setup_export_ready(&ctx_raw);
	setup_export_ready(&ctx_handle);

	/* The OSCORE master secret has the application AEAD key length. */
	const size_t ms_len =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0)
			->aead_key_length;

	uint8_t ms_raw[16] = { 0 };
	TEST_ASSERT_TRUE(0 != ms_len && ms_len <= sizeof(ms_raw));
	uint8_t salt_raw[8] = { 0 };
	uint8_t sid_raw[8] = { 0 };
	uint8_t rid_raw[8] = { 0 };
	size_t sid_raw_len = 0;
	size_t rid_raw_len = 0;
	int ret = edhoc_export_oscore_session_raw(
		&ctx_raw, ms_raw, ms_len, salt_raw, sizeof(salt_raw), sid_raw,
		sizeof(sid_raw), &sid_raw_len, rid_raw, sizeof(rid_raw),
		&rid_raw_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t ms_kid[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t salt_h[8] = { 0 };
	uint8_t sid_h[8] = { 0 };
	uint8_t rid_h[8] = { 0 };
	size_t sid_h_len = 0;
	size_t rid_h_len = 0;
	ret = edhoc_export_oscore_session(&ctx_handle, ms_kid, salt_h,
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
	uint8_t ms_ref[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	import_aead_ref(ms_kid, ms_raw, ms_len, ms_ref);

	uint8_t out_h[32] = { 0 };
	uint8_t out_r[32] = { 0 };
	const size_t out_h_len = aead_probe(ms_kid, out_h, sizeof(out_h));
	const size_t out_r_len = aead_probe(ms_ref, out_r, sizeof(out_r));
	TEST_ASSERT_EQUAL(out_h_len, out_r_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_h, out_r, out_h_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, ms_kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, ms_ref));

	edhoc_context_deinit(&ctx_raw);
	edhoc_context_deinit(&ctx_handle);
}

TEST_GROUP_RUNNER(exporters)
{
	RUN_TEST_CASE(exporters, error_get_code_success_default);
	RUN_TEST_CASE(exporters, error_get_code_after_set);

	RUN_TEST_CASE(exporters, error_get_cipher_suites_success);
	RUN_TEST_CASE(exporters, error_get_cipher_suites_peer_buffer_too_small);

	RUN_TEST_CASE(exporters, key_update_null_entropy);
	RUN_TEST_CASE(exporters, key_update_zero_entropy_length);
	RUN_TEST_CASE(exporters, key_update_bad_state_not_completed);

	RUN_TEST_CASE(exporters, oscore_session_raw_not_allowed);
	RUN_TEST_CASE(exporters, oscore_session_raw_bad_state_not_completed);

	RUN_TEST_CASE(exporters, export_raw_null_secret);
	RUN_TEST_CASE(exporters, export_raw_zero_length);
	RUN_TEST_CASE(exporters, export_raw_invalid_label);
	RUN_TEST_CASE(exporters, export_raw_bad_state);
	/* OSCORE CID CBOR encode failures */
	RUN_TEST_CASE(exporters, oscore_session_raw_sender_id_encode_fail);
	RUN_TEST_CASE(exporters, oscore_session_raw_recipient_id_encode_fail);

	/* edhoc_export (key handle) */
	RUN_TEST_CASE(exporters, export_null_ctx);
	RUN_TEST_CASE(exporters, export_null_key_id);
	RUN_TEST_CASE(exporters, export_context_null_nonzero_len);
	RUN_TEST_CASE(exporters, export_invalid_label);
	RUN_TEST_CASE(exporters, export_invalid_usage);
	RUN_TEST_CASE(exporters, export_bad_state);
	RUN_TEST_CASE(exporters, export_kdf_handle_matches_raw);
	RUN_TEST_CASE(exporters, export_aead_handle_success);

	/* edhoc_export_oscore_session (master secret handle) */
	RUN_TEST_CASE(exporters, oscore_session_null_master_secret_key_id);
	RUN_TEST_CASE(exporters, oscore_session_handle_matches_raw);
}
