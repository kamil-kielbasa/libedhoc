/**
 * \file    test_cipher_suite_pqc_1_x509_chain.c
 * \author  Kamil Kielbasa
 * \brief   Full EDHOC handshake integration test.
 *
 *          Scenario:
 *          - post-quantum cipher suite 1
 *            (ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256)
 *          - method 0 (signature / signature)
 *          - authentication via X.509 certificate chain
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver: */
#include "handshake_driver.h"
#include "handshake_credentials.h"

/* Test vector: */
#include "cipher_suite_pqc_1/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>

/* EDHOC internal header (ARRAY_SIZE): */
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

/* Signature identities authenticated with an ML-DSA-44 key. */
static const struct hs_identity initiator_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ML_DSA_44,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity responder_signature = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ML_DSA_44,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

/* Static function declarations -------------------------------------------- */

static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder);

/* Static function definitions --------------------------------------------- */

/* Assemble the pqc_1 scenario from the two endpoints and run the handshake. */
static void run_scenario(const char *name, enum edhoc_method method,
			 const struct handshake_endpoint *initiator,
			 const struct handshake_endpoint *responder)
{
	const enum edhoc_method methods[] = { method };

	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_PQC_1),
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

TEST_GROUP(cipher_suite_pqc_1_x509_chain);

TEST_SETUP(cipher_suite_pqc_1_x509_chain)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_pqc_1_x509_chain)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_pqc_1_x509_chain, method_0)
{
	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 1,
		.bstr_value = { 0x99 },
	};
	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 7,
	};

	const struct handshake_endpoint initiator = {
		.connection_id = init_cid,
		.own = &initiator_signature,
		.peer = &responder_signature,
		.ead = NULL,
	};
	const struct handshake_endpoint responder = {
		.connection_id = resp_cid,
		.own = &responder_signature,
		.peer = &initiator_signature,
		.ead = NULL,
	};

	run_scenario("cipher suite pqc_1, X.509 chain, method 0",
		     EDHOC_METHOD_0, &initiator, &responder);
}

TEST_GROUP_RUNNER(cipher_suite_pqc_1_x509_chain)
{
	RUN_TEST_CASE(cipher_suite_pqc_1_x509_chain, method_0);
}
