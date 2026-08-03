/**
 * \file    test_cipher_suite_2_x509_chain.c
 * \author  Kamil Kielbasa
 * \brief   Full EDHOC handshake integration test.
 *
 *          Scenario:
 *          - cipher suite 2 (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256)
 *          - authentication via X.509 certificate chain
 *          - every EDHOC method:
 *            - method 0 (signature / signature), without and with EAD
 *            - method 1 (signature / static DH)
 *            - method 2 (static DH / signature)
 *            - method 3 (static DH / static DH), with EAD
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

/* A P-256 static-DH public key is the X-coordinate of the uncompressed point
 * (0x04 || X || Y), i.e. the point without its leading tag byte. */
#define STATIC_DH_PUBLIC_KEY_LENGTH ((size_t)32)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/* Signature identities (ECDSA over SHA-256, full uncompressed public key). */
static const struct hs_identity initiator_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity responder_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

/* Static Diffie-Hellman identities (ECDH P-256, X-coordinate public key). */
static const struct hs_identity initiator_static_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_I[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity responder_static_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_R[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
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

/* Several tokens per message, in a distinct order on every message. */
static const struct hs_ead ead_multiple = {
	.message = {
		[EDHOC_MESSAGE_1] = { .token = { &ead_token_1, &ead_token_2,
						 &ead_token_3 },
				      .token_count = 3 },
		[EDHOC_MESSAGE_2] = { .token = { &ead_token_3, &ead_token_1 },
				      .token_count = 2 },
		[EDHOC_MESSAGE_3] = { .token = { &ead_token_3, &ead_token_2,
						 &ead_token_1 },
				      .token_count = 3 },
		[EDHOC_MESSAGE_4] = { .token = { &ead_token_1, &ead_token_4,
						 &ead_token_3 },
				      .token_count = 3 },
	},
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

TEST_GROUP(cipher_suite_2_x509_chain);

TEST_SETUP(cipher_suite_2_x509_chain)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_2_x509_chain)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_x509_chain, method_0)
{
	const uint8_t init_cid_value[] = { 0x0c };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0xff };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_signature,
		.peer = &responder_signature,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_signature,
		.peer = &initiator_signature,
		.ead = NULL,
	};

	run_scenario("cipher suite 2, X.509 chain, method 0", EDHOC_METHOD_0,
		     &initiator, &responder);
}

TEST(cipher_suite_2_x509_chain, method_0_with_ead)
{
	const uint8_t init_cid_value[] = { 0x33 };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0xa1, 0xb2, 0xc3 };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_signature,
		.peer = &responder_signature,
		.ead = &ead_multiple,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_signature,
		.peer = &initiator_signature,
		.ead = &ead_multiple,
	};

	run_scenario(
		"cipher suite 2, X.509 chain, method 0, multiple EAD tokens",
		EDHOC_METHOD_0, &initiator, &responder);
}

TEST(cipher_suite_2_x509_chain, method_1)
{
	const uint8_t init_cid_value[] = { 0x05 };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0x27 };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_signature,
		.peer = &responder_static_dh,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_static_dh,
		.peer = &initiator_signature,
		.ead = NULL,
	};

	run_scenario(
		"cipher suite 2, X.509 chain, method 1 (signature / static DH)",
		EDHOC_METHOD_1, &initiator, &responder);
}

TEST(cipher_suite_2_x509_chain, method_2)
{
	const uint8_t init_cid_value[] = { 0x2c, 0x2d };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0x15 };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_static_dh,
		.peer = &responder_signature,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_signature,
		.peer = &initiator_static_dh,
		.ead = NULL,
	};

	run_scenario(
		"cipher suite 2, X.509 chain, method 2 (static DH / signature)",
		EDHOC_METHOD_2, &initiator, &responder);
}

TEST(cipher_suite_2_x509_chain, method_3_with_ead)
{
	const uint8_t init_cid_value[] = { 0x0a, 0x0b };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0x0c, 0x0d, 0x0e, 0x0f };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_static_dh,
		.peer = &responder_static_dh,
		.ead = &ead_single,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_static_dh,
		.peer = &initiator_static_dh,
		.ead = &ead_single,
	};

	run_scenario(
		"cipher suite 2, X.509 chain, method 3 (static DH / static DH)",
		EDHOC_METHOD_3, &initiator, &responder);
}

TEST_GROUP_RUNNER(cipher_suite_2_x509_chain)
{
	RUN_TEST_CASE(cipher_suite_2_x509_chain, method_0);
	RUN_TEST_CASE(cipher_suite_2_x509_chain, method_0_with_ead);
	RUN_TEST_CASE(cipher_suite_2_x509_chain, method_1);
	RUN_TEST_CASE(cipher_suite_2_x509_chain, method_2);
	RUN_TEST_CASE(cipher_suite_2_x509_chain, method_3_with_ead);
}
