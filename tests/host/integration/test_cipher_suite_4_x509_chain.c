/**
 * \file    test_cipher_suite_4_x509_chain.c
 * \author  Kamil Kielbasa
 * \brief   Full EDHOC handshake integration test.
 *
 *          Scenario:
 *          - cipher suite 4 (X25519 / EdDSA / ChaCha20-Poly1305 / SHA-256)
 *          - method 0 (signature / signature)
 *          - authentication via X.509 certificate chain:
 *            - one certificate
 *            - two-certificate chain (leaf + CA)
 *
 *          Suite 4 shares suite 0's X25519 / EdDSA credentials (only the AEAD
 *          differs), so it reuses the suite-0 Ed25519 test vectors.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver: */
#include "handshake_driver.h"
#include "handshake_credentials.h"

/* Test vector (shared with suite 0: identical X25519 / EdDSA credentials): */
#include "cipher_suite_0/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>

/* EDHOC internal header: */
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct hs_identity initiator_one_certificate = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_RAW_ED25519,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity responder_one_certificate = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_RAW_ED25519,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

static const struct hs_identity initiator_two_certificates = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) },
		  { .pointer = CRED_CA, .length = ARRAY_SIZE(CRED_CA) } },
	.cert_count = 2,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_RAW_ED25519,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity responder_two_certificates = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) },
		  { .pointer = CRED_CA, .length = ARRAY_SIZE(CRED_CA) } },
	.cert_count = 2,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_RAW_ED25519,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

/* Static function declarations -------------------------------------------- */

static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder);

/* Static function definitions --------------------------------------------- */

/* Assemble the suite-4 scenario from the two endpoints and run the handshake. */
static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder)
{
	const enum edhoc_method methods[] = { method };

	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_4),
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

TEST_GROUP(cipher_suite_4_x509_chain);

TEST_SETUP(cipher_suite_4_x509_chain)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_4_x509_chain)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_4_x509_chain, method_0_one_certificate)
{
	const uint8_t init_cid_value[] = { 0x00 };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0x01 };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_one_certificate,
		.peer = &responder_one_certificate,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_one_certificate,
		.peer = &initiator_one_certificate,
		.ead = NULL,
	};

	run_scenario("cipher suite 4, X.509 chain, method 0, one certificate",
		     EDHOC_METHOD_0, &initiator, &responder);
}

TEST(cipher_suite_4_x509_chain, method_0_two_certificate_chain)
{
	const uint8_t init_cid_value[] = { 0x20 };
	const struct edhoc_buffer init_cid = {
		.value = init_cid_value,
		.length = ARRAY_SIZE(init_cid_value),
	};
	const uint8_t resp_cid_value[] = { 0x02, 0x03 };
	const struct edhoc_buffer resp_cid = {
		.value = resp_cid_value,
		.length = ARRAY_SIZE(resp_cid_value),
	};

	const struct handshake_endpoint initiator = {
		.role = EDHOC_ROLE_INITIATOR,
		.connection_id = init_cid,
		.own = &initiator_two_certificates,
		.peer = &responder_two_certificates,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.role = EDHOC_ROLE_RESPONDER,
		.connection_id = resp_cid,
		.own = &responder_two_certificates,
		.peer = &initiator_two_certificates,
		.ead = NULL,
	};

	run_scenario("cipher suite 4, X.509 chain, method 0, two certificates",
		     EDHOC_METHOD_0, &initiator, &responder);
}

TEST_GROUP_RUNNER(cipher_suite_4_x509_chain)
{
	RUN_TEST_CASE(cipher_suite_4_x509_chain, method_0_one_certificate);
	RUN_TEST_CASE(cipher_suite_4_x509_chain,
		      method_0_two_certificate_chain);
}
