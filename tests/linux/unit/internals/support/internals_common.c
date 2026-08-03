/**
 * \file    internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Shared fixtures for internals unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/** P-256 uncompressed public key: 0x04 || X || Y (1 + 32 + 32 bytes). */
#define INTERNALS_P256_UNCOMPRESSED_KEY_LEN ((size_t)65)

/** P-256 coordinate length; EDHOC transports only the X coordinate. */
#define INTERNALS_P256_COORD_LEN ((size_t)32)

/** P-256 key size in bits. */
#define INTERNALS_P256_KEY_BITS ((size_t)256)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

static int
internals_cred_select_local_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_credential_selected *selected);
static int internals_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);
static void internals_platform_zeroize(void *buffer, size_t length);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_credentials internals_cred_stubs = {
	.select_local = internals_cred_select_local_stub,
	.authenticate_peer = internals_cred_authenticate_peer_stub,
};

static const struct edhoc_platform internals_platform = {
	.zeroize = internals_platform_zeroize,
};

/* Static function definitions --------------------------------------------- */

static int
internals_cred_select_local_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_credential_selected *selected)
{
	static const uint8_t dummy_cert[] = { 0x30, 0x00 };

	(void)user_ctx;
	(void)call_ctx;

	if (NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
	selected->x509_chain.count = 1;
	selected->x509_chain.certificate[0].value = dummy_cert;
	selected->x509_chain.certificate[0].length = ARRAY_SIZE(dummy_cert);

	memset(selected->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

static int internals_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	static const uint8_t dummy_key[INTERNALS_P256_COORD_LEN] = { 0 };

	(void)user_ctx;
	(void)call_ctx;
	(void)received;

	if (NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	trusted->public_key.value = dummy_key;
	trusted->public_key.length = ARRAY_SIZE(dummy_key);

	return EDHOC_SUCCESS;
}

static void internals_platform_zeroize(void *buffer, size_t length)
{
	(void)memset(buffer, 0, length);
}

/* Module interface function definitions ----------------------------------- */

const struct edhoc_platform *internals_get_platform(void)
{
	return &internals_platform;
}

void internals_setup_crypto_context(struct edhoc_context *ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	const uint8_t cid_value[] = { 0x01 };
	const struct edhoc_buffer cid = {
		.value = cid_value,
		.length = ARRAY_SIZE(cid_value),
	};

	int ret = 0;

	memset(ctx, 0, sizeof(*ctx));

	ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(
		ctx, edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(ctx, &internals_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, &internals_platform);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void internals_inject_prk(struct edhoc_context *ctx,
			  enum edhoc_key_slot_id slot, const uint8_t *prk,
			  size_t prk_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, prk, prk_len, &kid);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	memcpy(ctx->key_slots[slot].key_id, &kid, sizeof(kid));
	ctx->key_slots[slot].present = true;
}

void internals_inject_ecdh_key(uint8_t *key_id, const uint8_t *priv,
			       size_t priv_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, priv, priv_len, &kid);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	memcpy(key_id, &kid, sizeof(kid));
}

void internals_make_ecdh_peer_pub(uint8_t *out, size_t out_size,
				  size_t *out_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, INTERNALS_P256_KEY_BITS);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t status = psa_generate_key(&attr, &kid);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	/* Uncompressed point is 0x04 | X | Y; EDHOC transports the 32-byte X. */
	uint8_t uncomp[INTERNALS_P256_UNCOMPRESSED_KEY_LEN] = { 0 };
	size_t uncomp_len = 0;

	status =
		psa_export_public_key(kid, uncomp, sizeof(uncomp), &uncomp_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	status = psa_destroy_key(kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	TEST_ASSERT_EQUAL(INTERNALS_P256_UNCOMPRESSED_KEY_LEN, uncomp_len);
	TEST_ASSERT_TRUE(out_size >= INTERNALS_P256_COORD_LEN);

	memcpy(out, &uncomp[1], INTERNALS_P256_COORD_LEN);
	*out_len = INTERNALS_P256_COORD_LEN;
}
