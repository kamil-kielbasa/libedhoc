/**
 * \file    benchmark_suite_4.c
 * \author  Kamil Kielbasa
 * \brief   Cipher suite 4 (X25519 / EdDSA / ChaCha20-Poly1305) benchmark case.
 *
 *          Suite 4 shares suite 0's X25519 / EdDSA credentials (only the AEAD
 *          differs), so it reuses the suite-0 Ed25519 test vectors.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Benchmark harness: */
#include "benchmark_suite.h"
#include "benchmark_credentials.h"

/* Test vector (shared with suite 0: identical X25519 / EdDSA credentials): */
#include "cipher_suite_0/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>
#include "edhoc_macros_internal.h"

/* Zephyr headers: */
#include <zephyr/ztest.h>

/* Module interface function definitions ----------------------------------- */

ZTEST(edhoc_benchmark, test_suite_4_x25519_chacha20)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };

	/* Both identifiers travel in the compact form of
	 * RFC 9528: 3.3.2, so the benchmark measures the common case. */
	const uint8_t initiator_cid[] = { 0x0c };
	const uint8_t responder_cid[] = { 0x2b };

	const struct benchmark_identity initiator = {
		.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
		.cert = { { .pointer = CRED_I, .length = ARRAY_SIZE(CRED_I) } },
		.cert_count = 1,
		.private_key = SK_I,
		.private_key_length = ARRAY_SIZE(SK_I),
		.key_import = BENCHMARK_KEY_RAW_ED25519,
		.public_key = PK_I,
		.public_key_length = ARRAY_SIZE(PK_I),
	};

	const struct benchmark_identity responder = {
		.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
		.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
		.cert_count = 1,
		.private_key = SK_R,
		.private_key_length = ARRAY_SIZE(SK_R),
		.key_import = BENCHMARK_KEY_RAW_ED25519,
		.public_key = PK_R,
		.public_key_length = ARRAY_SIZE(PK_R),
	};

	const struct benchmark_case bench_case = {
		.name = "cipher suite 4 (X25519 / EdDSA / ChaCha20-Poly1305 / SHA-256), method 0, no EAD",
		.suite_id = EDHOC_CIPHER_SUITE_4,
		.methods = methods,
		.methods_count = ARRAY_SIZE(methods),
		.initiator_connection_id = {
			.value = initiator_cid,
			.length = ARRAY_SIZE(initiator_cid),
		},
		.responder_connection_id = {
			.value = responder_cid,
			.length = ARRAY_SIZE(responder_cid),
		},
		.initiator = &initiator,
		.responder = &responder,
	};

	benchmark_run_case(&bench_case);
}
