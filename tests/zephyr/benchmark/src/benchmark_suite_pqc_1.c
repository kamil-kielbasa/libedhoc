/**
 * \file    benchmark_suite_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Cipher suite pqc_1 (ML-KEM-512 / ML-DSA-44) benchmark case.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Benchmark harness: */
#include "benchmark_suite.h"
#include "benchmark_credentials.h"

/* Test vector: */
#include "cipher_suite_pqc_1/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>
#include "edhoc_macros_internal.h"

/* PSA crypto + liboqs headers: */
#include <psa/crypto.h>
#include <oqs/rand.h>

/* Zephyr headers: */
#include <zephyr/ztest.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Static function declarations -------------------------------------------- */

static void benchmark_oqs_randombytes(uint8_t *random_array,
				      size_t bytes_to_read);

/* Static function definitions --------------------------------------------- */

/* liboqs has no system RNG in an embedded build (OQS_EMBEDDED_BUILD), so the
 * application must supply one; PSA is initialised before any ML-KEM / ML-DSA
 * operation runs. */
static void benchmark_oqs_randombytes(uint8_t *random_array,
				      size_t bytes_to_read)
{
	(void)psa_generate_random(random_array, bytes_to_read);
}

/* Module interface function definitions ----------------------------------- */

ZTEST(edhoc_benchmark, test_suite_pqc_1_mlkem512_mldsa44)
{
	OQS_randombytes_custom_algorithm(benchmark_oqs_randombytes);

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
		.key_import = BENCHMARK_KEY_ML_DSA_44,
		.public_key = PK_I,
		.public_key_length = ARRAY_SIZE(PK_I),
	};

	const struct benchmark_identity responder = {
		.cose_header = EDHOC_COSE_HEADER_X509_CHAIN,
		.cert = { { .pointer = CRED_R, .length = ARRAY_SIZE(CRED_R) } },
		.cert_count = 1,
		.private_key = SK_R,
		.private_key_length = ARRAY_SIZE(SK_R),
		.key_import = BENCHMARK_KEY_ML_DSA_44,
		.public_key = PK_R,
		.public_key_length = ARRAY_SIZE(PK_R),
	};

	const struct benchmark_case bench_case = {
		.name = "cipher suite pqc_1 (ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256), method 0, no EAD",
		.suite_id = EDHOC_CIPHER_SUITE_PQC_1,
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
