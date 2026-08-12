/**
 * \file    test_cipher_suite_2_mixed_credentials.c
 * \author  Kamil Kielbasa
 * \brief   Full EDHOC handshake integration test with asymmetric credentials.
 *
 *          The two peers authenticate with *different* credential types, which
 *          RFC 9528 allows and which the shared handshake driver expresses by
 *          giving each \ref hs_identity its own COSE header. Every pairing runs
 *          in both directions, and a key identifier appears with both credential
 *          formats: a CCS raw public key (CBOR encoded) and a DER certificate
 *          the identifier alone selects (raw).
 *
 *          Scenario:
 *          - cipher suite 2 (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256)
 *          - all four methods, so every credential type is exercised with a
 *            signature key and with a static Diffie-Hellman key
 *          - EAD passed per scenario, one token per message
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
#include <stddef.h>
#include <stdint.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/* COSE algorithm identifier SHA-256/64, declared in the x5t thumbprint. */
#define COSE_ALGORITHM_SHA_256_64 (-15)

/* A static DH public key is the X coordinate alone. */
#define STATIC_DH_PUBLIC_KEY_LENGTH ((size_t)32)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/* Signature identities: ECDSA over SHA-256, full uncompressed public key. */
static const struct hs_identity init_kid_ccs_sig = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_I,
	.kid_length = ARRAY_SIZE(KID_I),
	.credential = CCS_I,
	.credential_length = ARRAY_SIZE(CCS_I),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity resp_kid_ccs_sig = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_R,
	.kid_length = ARRAY_SIZE(KID_R),
	.credential = CCS_R,
	.credential_length = ARRAY_SIZE(CCS_R),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

/* The identifier selects the leaf certificate itself, so CRED is raw DER. */
static const struct hs_identity init_kid_der_sig = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_I,
	.kid_length = ARRAY_SIZE(KID_I),
	.credential = CRED_I,
	.credential_length = ARRAY_SIZE(CRED_I),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_RAW,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity resp_kid_der_sig = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_R,
	.kid_length = ARRAY_SIZE(KID_R),
	.credential = CRED_R,
	.credential_length = ARRAY_SIZE(CRED_R),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_RAW,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

/* RFC 9528: Appendix F uses ID_CRED_I = { 4 : h'' }, so an empty identifier
 * has to survive the round trip. */
static const struct hs_identity resp_kid_empty_sig = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = NULL,
	.kid_length = 0,
	.credential = CRED_R,
	.credential_length = ARRAY_SIZE(CRED_R),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_RAW,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

static const struct hs_identity init_chain_sig = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_I,
	.public_key_length = ARRAY_SIZE(PK_I),
};

static const struct hs_identity resp_chain_sig = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDSA_SHA256,
	.public_key = PK_R,
	.public_key_length = ARRAY_SIZE(PK_R),
};

static const struct hs_identity init_hash_sig = {
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

static const struct hs_identity resp_hash_sig = {
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

/* Static Diffie-Hellman identities: the same keys imported for ECDH, whose
 * public part is the X coordinate alone. */
static const struct hs_identity init_kid_ccs_dh = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_I,
	.kid_length = ARRAY_SIZE(KID_I),
	.credential = CCS_I,
	.credential_length = ARRAY_SIZE(CCS_I),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_I[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity resp_kid_ccs_dh = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_R,
	.kid_length = ARRAY_SIZE(KID_R),
	.credential = CCS_R,
	.credential_length = ARRAY_SIZE(CCS_R),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_R[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity init_kid_der_dh = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_I,
	.kid_length = ARRAY_SIZE(KID_I),
	.credential = CRED_I,
	.credential_length = ARRAY_SIZE(CRED_I),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_RAW,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_I[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity resp_kid_der_dh = {
	.cose_header = EDHOC_COSE_HEADER_KID,
	.kid = KID_R,
	.kid_length = ARRAY_SIZE(KID_R),
	.credential = CRED_R,
	.credential_length = ARRAY_SIZE(CRED_R),
	.credential_format = EDHOC_CREDENTIAL_FORMAT_RAW,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_R[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity init_chain_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_I[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity resp_chain_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_R[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
};

static const struct hs_identity init_hash_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_HASH,
	.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
	.cert_count = 1,
	.private_key = SK_I,
	.private_key_length = ARRAY_SIZE(SK_I),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_I[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
	.thumbprint = CRED_I_thumbprint,
	.thumbprint_length = ARRAY_SIZE(CRED_I_thumbprint),
	.thumbprint_algorithm = COSE_ALGORITHM_SHA_256_64,
};

static const struct hs_identity resp_hash_dh = {
	.cose_header = EDHOC_COSE_HEADER_X509_HASH,
	.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
	.cert_count = 1,
	.private_key = SK_R,
	.private_key_length = ARRAY_SIZE(SK_R),
	.key_import = HS_KEY_ECDH_P256,
	.public_key = &PK_R[1],
	.public_key_length = STATIC_DH_PUBLIC_KEY_LENGTH,
	.thumbprint = CRED_R_thumbprint,
	.thumbprint_length = ARRAY_SIZE(CRED_R_thumbprint),
	.thumbprint_algorithm = COSE_ALGORITHM_SHA_256_64,
};

/* The Initiator sends a compact one-byte identifier, the Responder a byte
 * string, so both encodings of RFC 9528: 3.3.2 appear in every scenario. */
static const uint8_t initiator_connection_id_value[] = { 0x17 };
static const struct edhoc_buffer initiator_connection_id = {
	.value = initiator_connection_id_value,
	.length = ARRAY_SIZE(initiator_connection_id_value),
};

static const uint8_t responder_connection_id_value[] = { 0x7a, 0x7b };
static const struct edhoc_buffer responder_connection_id = {
	.value = responder_connection_id_value,
	.length = ARRAY_SIZE(responder_connection_id_value),
};

static const uint8_t ead_value_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

static const uint8_t ead_value_2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				       0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t ead_value_3[] = { 0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64,
				       0xd5, 0x79, 0x5d, 0x39, 0x09, 0x71 };

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
			 const struct hs_identity *initiator_identity,
			 const struct hs_identity *responder_identity,
			 const struct hs_ead *ead);

/* Static function definitions --------------------------------------------- */

/* Pair the two identities into a scenario and run the handshake. Each endpoint
 * presents its own identity and expects the other one from the peer. */
static void run_scenario(const char *name, enum edhoc_method method,
			 const struct hs_identity *initiator_identity,
			 const struct hs_identity *responder_identity,
			 const struct hs_ead *ead)
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
		.init = {
			.role = EDHOC_ROLE_INITIATOR,
			.connection_id = initiator_connection_id,
			.own = initiator_identity,
			.peer = responder_identity,
			.ead = ead,
		},
		.resp = {
			.role = EDHOC_ROLE_RESPONDER,
			.connection_id = responder_connection_id,
			.own = responder_identity,
			.peer = initiator_identity,
			.ead = ead,
		},
	};

	run_handshake(&scenario);
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_2_mixed_credentials);

TEST_SETUP(cipher_suite_2_mixed_credentials)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_2_mixed_credentials)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_mixed_credentials, method_0_kid_ccs_and_chain)
{
	run_scenario("method 0, kid (CCS) / X.509 chain", EDHOC_METHOD_0,
		     &init_kid_ccs_sig, &resp_chain_sig, &ead_single);
	run_scenario("method 0, X.509 chain / kid (CCS)", EDHOC_METHOD_0,
		     &init_chain_sig, &resp_kid_ccs_sig, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_0_kid_der_and_chain)
{
	run_scenario("method 0, kid (DER) / X.509 chain", EDHOC_METHOD_0,
		     &init_kid_der_sig, &resp_chain_sig, &ead_single);
	run_scenario("method 0, X.509 chain / kid (DER)", EDHOC_METHOD_0,
		     &init_chain_sig, &resp_kid_der_sig, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_0_chain_and_hash)
{
	run_scenario("method 0, X.509 chain / X.509 hash", EDHOC_METHOD_0,
		     &init_chain_sig, &resp_hash_sig, &ead_single);
	run_scenario("method 0, X.509 hash / X.509 chain", EDHOC_METHOD_0,
		     &init_hash_sig, &resp_chain_sig, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_0_empty_kid)
{
	run_scenario("method 0, X.509 chain / kid h''", EDHOC_METHOD_0,
		     &init_chain_sig, &resp_kid_empty_sig, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_1_signature_and_static_dh)
{
	run_scenario("method 1, kid (CCS) / X.509 chain", EDHOC_METHOD_1,
		     &init_kid_ccs_sig, &resp_chain_dh, NULL);
	run_scenario("method 1, X.509 hash / kid (DER)", EDHOC_METHOD_1,
		     &init_hash_sig, &resp_kid_der_dh, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_2_static_dh_and_signature)
{
	run_scenario("method 2, X.509 chain / kid (CCS)", EDHOC_METHOD_2,
		     &init_chain_dh, &resp_kid_ccs_sig, NULL);
	run_scenario("method 2, kid (DER) / X.509 hash", EDHOC_METHOD_2,
		     &init_kid_der_dh, &resp_hash_sig, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_3_kid_ccs_and_chain)
{
	run_scenario("method 3, kid (CCS) / X.509 chain", EDHOC_METHOD_3,
		     &init_kid_ccs_dh, &resp_chain_dh, &ead_single);
	run_scenario("method 3, X.509 chain / kid (CCS)", EDHOC_METHOD_3,
		     &init_chain_dh, &resp_kid_ccs_dh, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_3_kid_der_and_chain)
{
	run_scenario("method 3, kid (DER) / X.509 chain", EDHOC_METHOD_3,
		     &init_kid_der_dh, &resp_chain_dh, &ead_single);
	run_scenario("method 3, X.509 chain / kid (DER)", EDHOC_METHOD_3,
		     &init_chain_dh, &resp_kid_der_dh, &ead_single);
}

TEST(cipher_suite_2_mixed_credentials, method_3_chain_and_hash)
{
	run_scenario("method 3, X.509 chain / X.509 hash", EDHOC_METHOD_3,
		     &init_chain_dh, &resp_hash_dh, &ead_single);
	run_scenario("method 3, X.509 hash / X.509 chain", EDHOC_METHOD_3,
		     &init_hash_dh, &resp_chain_dh, &ead_single);
}

TEST_GROUP_RUNNER(cipher_suite_2_mixed_credentials)
{
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_0_kid_ccs_and_chain);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_0_kid_der_and_chain);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_0_chain_and_hash);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials, method_0_empty_kid);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_1_signature_and_static_dh);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_2_static_dh_and_signature);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_3_kid_ccs_and_chain);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_3_kid_der_and_chain);
	RUN_TEST_CASE(cipher_suite_2_mixed_credentials,
		      method_3_chain_and_hash);
}
