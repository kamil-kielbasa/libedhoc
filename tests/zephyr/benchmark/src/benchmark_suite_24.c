/**
 * \file    benchmark_suite_24.c
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 24 (P-384 / ES384) benchmark case.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Benchmark harness: */
#include "benchmark_suite.h"
#include "benchmark_credentials.h"

/* Test vector: */
#include "cipher_suite_24/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>
#include "edhoc_macros_internal.h"

/* Zephyr headers: */
#include <zephyr/ztest.h>

/* Module interface function definitions ----------------------------------- */

ZTEST(edhoc_benchmark, test_suite_24_p384_es384)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };

	const struct benchmark_identity initiator = {
		.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
		.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
		.cert_count = 1,
		.private_key = SK_I,
		.private_key_length = ARRAY_SIZE(SK_I),
		.key_import = BENCHMARK_KEY_ECDSA_SHA384,
		.public_key = PK_I,
		.public_key_length = ARRAY_SIZE(PK_I),
	};

	const struct benchmark_identity responder = {
		.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
		.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
		.cert_count = 1,
		.private_key = SK_R,
		.private_key_length = ARRAY_SIZE(SK_R),
		.key_import = BENCHMARK_KEY_ECDSA_SHA384,
		.public_key = PK_R,
		.public_key_length = ARRAY_SIZE(PK_R),
	};

	const struct benchmark_case bench_case = {
		.name = "cipher suite 24 (P-384 / ES384 / A256GCM / SHA-384), method 0, no EAD",
		.suite_id = EDHOC_CIPHER_SUITE_24,
		.methods = methods,
		.methods_count = ARRAY_SIZE(methods),
		.initiator_connection_id = {
			.encode_type =
				EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
			.int_value = 12,
		},
		.responder_connection_id = {
			.encode_type =
				EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
			.int_value = -12,
		},
		.initiator = &initiator,
		.responder = &responder,
	};

	benchmark_run_case(&bench_case);
}
