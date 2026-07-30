/**
 * \file    test_cipher_suite_2_x509_hash.c
 * \author  Kamil Kielbasa
 * \brief   Full EDHOC handshake integration test.
 *
 *          Scenario:
 *          - cipher suite 2 (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256)
 *          - method 0 (signature / signature)
 *          - authentication via X.509 certificate hash (COSE x5t thumbprint)
 *          - one EAD token per message
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver: */
#include "handshake_driver.h"
#include "handshake_credentials.h"
#include "handshake_ead.h"

/* Test vector: */
#include "cipher_suite_2/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/ead.h>

/* EDHOC internal header (ARRAY_SIZE): */
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/* COSE algorithm identifier SHA-256/64, declared in the x5t thumbprint. */
#define COSE_ALGORITHM_SHA_256_64 (-15)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/* Signature identities identified by an x5t certificate thumbprint. */
static const struct hs_identity initiator_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_HASH,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
	.thumbprint = CRED_I_thumbprint,
	.thumbprint_length = ARRAY_SIZE(CRED_I_thumbprint),
	.thumbprint_algorithm = COSE_ALGORITHM_SHA_256_64,
};

static const struct hs_identity responder_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_HASH,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
	.thumbprint = CRED_R_thumbprint,
	.thumbprint_length = ARRAY_SIZE(CRED_R_thumbprint),
	.thumbprint_algorithm = COSE_ALGORITHM_SHA_256_64,
};

static const uint8_t ead_value_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

static const uint8_t ead_value_2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				       0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t ead_value_3[] = {
	0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79, 0x5d, 0x39, 0x09, 0x71,
	0x8c, 0xdd, 0x05, 0xab, 0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
	0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd, 0x3c, 0xb2, 0x5f, 0x25,
	0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
	0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const uint8_t ead_value_4[] = {
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00
};

static const struct edhoc_ead_token ead_token_1 = {
	.label = 0,
	.value = { .value = ead_value_1, .length = ARRAY_SIZE(ead_value_1) },
};

static const struct edhoc_ead_token ead_token_2 = {
	.label = 24,
	.value = { .value = ead_value_2, .length = ARRAY_SIZE(ead_value_2) },
};

static const struct edhoc_ead_token ead_token_3 = {
	.label = 65535,
	.value = { .value = ead_value_3, .length = ARRAY_SIZE(ead_value_3) },
};

static const struct edhoc_ead_token ead_token_4 = {
	.label = -830,
	.value = { .value = ead_value_4, .length = ARRAY_SIZE(ead_value_4) },
};

/* One token per message. */
static const struct hs_ead ead_single = {
	.message = {
		[EDHOC_MESSAGE_1] = { .token = { &ead_token_1 },
				      .token_count = 1 },
		[EDHOC_MESSAGE_2] = { .token = { &ead_token_2 },
				      .token_count = 1 },
		[EDHOC_MESSAGE_3] = { .token = { &ead_token_3 },
				      .token_count = 1 },
		[EDHOC_MESSAGE_4] = { .token = { &ead_token_4 },
				      .token_count = 1 },
	},
};

/* Static function declarations -------------------------------------------- */

static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder);

/* Static function definitions --------------------------------------------- */

/* Assemble the suite-2 scenario from the two endpoints and run the handshake. */
static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder)
{
	const enum edhoc_method methods[] = { method };

	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2),
	};

	const struct handshake_scenario scenario = {
		.name = name,
		.methods = methods,
		.methods_count = ARRAY_SIZE(methods),
		.cipher_suites = cipher_suites,
		.cipher_suites_count = ARRAY_SIZE(cipher_suites),
		.platform = hs_platform(),
		.init = *initiator,
		.resp = *responder,
	};

	run_handshake(&scenario);
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_2_x509_hash);

TEST_SETUP(cipher_suite_2_x509_hash)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_2_x509_hash)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_x509_hash, method_0)
{
	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 23,
	};
	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 2,
		.bstr_value = { 0x7a, 0x7b },
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_signature,
		.peer = &responder_signature,
		.ead = &ead_single,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_signature,
		.peer = &initiator_signature,
		.ead = &ead_single,
	};

	run_scenario("cipher suite 2, X.509 hash, method 0", EDHOC_METHOD_0,
		     &initiator, &responder);
}

TEST_GROUP_RUNNER(cipher_suite_2_x509_hash)
{
	RUN_TEST_CASE(cipher_suite_2_x509_hash, method_0);
}
