/**
 * \file    benchmark_suite.c
 * \author  Kamil Kielbasa
 * \brief   Benchmark harness: shared platform, timed EDHOC handshake spine and
 *          cipher-suite case runner.
 *
 *          Runs the full EDHOC handshake described by a \ref benchmark_case
 *          for CONFIG_EDHOC_BENCHMARK_ITERATIONS iterations, timing every
 *          message phase, and emits the JSON report.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Benchmark harness: */
#include "benchmark_suite.h"
#include "benchmark_credentials.h"
#include "benchmark_ead.h"
#include "benchmark_report.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/platform.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Zephyr headers: */
#include <zephyr/ztest.h>
#include <zephyr/kernel.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* External library hooks -------------------------------------------------- */

/* The post-quantum suite keeps credential keys in a software keystore the EDHOC
 * context does not own. This library-internal hook releases them between
 * handshakes; it is declared here (not in a public header) exactly as the
 * suite's edhoc_cipher_suite_pqc_1.c exposes it. Only referenced when the
 * post-quantum suite is built (one benchmark scenario per suite). */
#if defined(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
extern void edhoc_cipher_suite_pqc_1_keystore_release_all(void);
#endif

/* Module defines ---------------------------------------------------------- */

/* Message buffer size. 16 KiB: large enough for a full X.509 certificate chain
 * together with the post-quantum suite's message 3 (the ML-DSA-44 signature is
 * ~2420 bytes) and EAD. */
#define BENCHMARK_MESSAGE_BUFFER_SIZE KB(16)

/* OSCORE security-context sizes (RFC 9528 Appendix A.1 defaults), used only to
 * check that both peers derived identical key material after the handshake. */
#define BENCHMARK_OSCORE_SECRET_LEN ((size_t)16)
#define BENCHMARK_OSCORE_SALT_LEN ((size_t)8)
#define BENCHMARK_OSCORE_ID_MAX ((size_t)8)

/* Time one handshake phase: run \p call, measure it with the benchmark clock,
 * assert it succeeded, record the sample under \p phase_id and fold it into the
 * running total. Expands against the local variables (start, result, total_ns)
 * of benchmark_run_handshake, so it is only usable there. */
#define BENCHMARK_TIME_PHASE(phase_id, call)                                \
	do {                                                                \
		start = benchmark_timestamp_ns();                           \
		const int phase_ret = (call);                               \
		const uint64_t phase_ns = benchmark_timestamp_ns() - start; \
		zassert_ok(phase_ret, "phase %d failed", (int)(phase_id));  \
		benchmark_result_add(result, (phase_id), phase_ns);         \
		total_ns += phase_ns;                                       \
	} while (0)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/* The generic credential and EAD callbacks; only the per-endpoint data differs,
 * and it travels via the bound user context. */
static const struct edhoc_credentials benchmark_credentials_interface = {
	.select_local = benchmark_credentials_select_local,
	.authenticate_peer = benchmark_credentials_authenticate_peer,
};

static const struct edhoc_ead benchmark_ead_interface = {
	.compose = benchmark_ead_compose,
	.process = benchmark_ead_process,
};

/* Static function declarations -------------------------------------------- */

static void benchmark_platform_zeroize(void *buffer, size_t length);
static const struct edhoc_platform *benchmark_platform(void);
static void benchmark_assert_shared_secrets(struct edhoc_context *init_ctx,
					    struct edhoc_context *resp_ctx);
static void benchmark_setup_context(struct edhoc_context *ctx,
				    const struct benchmark_case *bench_case,
				    const struct benchmark_endpoint *endpoint);
static void benchmark_run_handshake(const struct benchmark_case *bench_case,
				    struct benchmark_result *result);

/* Static function definitions --------------------------------------------- */

/* The benchmark runs under a non-eliding build rather than an optimizer that
 * might drop a plain wipe, so memset is enough here. */
static void benchmark_platform_zeroize(void *buffer, size_t length)
{
	memset(buffer, 0, length);
}

static const struct edhoc_platform *benchmark_platform(void)
{
	static const struct edhoc_platform platform = {
		.zeroize = benchmark_platform_zeroize,
	};

	return &platform;
}

static void benchmark_setup_context(struct edhoc_context *ctx,
				    const struct benchmark_case *bench_case,
				    const struct benchmark_endpoint *endpoint)
{
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(bench_case->suite_id);
	zassert_not_null(params, "cipher suite %d is not built in",
			 (int)bench_case->suite_id);
	const struct edhoc_cipher_suite cipher_suites[] = { *params };

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(bench_case->suite_id);
	zassert_not_null(crypto, "no crypto backend for the cipher suite");

	zassert_ok(edhoc_context_init(ctx));
	zassert_ok(edhoc_set_methods(ctx, bench_case->methods,
				     bench_case->methods_count));
	zassert_ok(edhoc_set_cipher_suites(ctx, cipher_suites,
					   ARRAY_SIZE(cipher_suites)));
	zassert_ok(edhoc_set_connection_id(ctx, &endpoint->connection_id));
	zassert_ok(edhoc_set_user_context(ctx, (void *)endpoint));

	if (NULL != endpoint->ead) {
		zassert_ok(edhoc_bind_ead(ctx, &benchmark_ead_interface));
	}

	zassert_ok(edhoc_bind_crypto(ctx, crypto));
	zassert_ok(edhoc_bind_platform(ctx, benchmark_platform()));
	zassert_ok(
		edhoc_bind_credentials(ctx, &benchmark_credentials_interface));
}

static void benchmark_assert_shared_secrets(struct edhoc_context *init_ctx,
					    struct edhoc_context *resp_ctx)
{
	uint8_t init_master_secret[BENCHMARK_OSCORE_SECRET_LEN] = { 0 };
	uint8_t init_master_salt[BENCHMARK_OSCORE_SALT_LEN] = { 0 };
	uint8_t init_sender_id[BENCHMARK_OSCORE_ID_MAX] = { 0 };
	uint8_t init_recipient_id[BENCHMARK_OSCORE_ID_MAX] = { 0 };
	size_t init_sender_id_len = 0;
	size_t init_recipient_id_len = 0;

	zassert_ok(edhoc_export_oscore_context_raw(
		init_ctx, init_master_secret, sizeof(init_master_secret),
		init_master_salt, sizeof(init_master_salt), init_sender_id,
		sizeof(init_sender_id), &init_sender_id_len, init_recipient_id,
		sizeof(init_recipient_id), &init_recipient_id_len));

	uint8_t resp_master_secret[BENCHMARK_OSCORE_SECRET_LEN] = { 0 };
	uint8_t resp_master_salt[BENCHMARK_OSCORE_SALT_LEN] = { 0 };
	uint8_t resp_sender_id[BENCHMARK_OSCORE_ID_MAX] = { 0 };
	uint8_t resp_recipient_id[BENCHMARK_OSCORE_ID_MAX] = { 0 };
	size_t resp_sender_id_len = 0;
	size_t resp_recipient_id_len = 0;

	zassert_ok(edhoc_export_oscore_context_raw(
		resp_ctx, resp_master_secret, sizeof(resp_master_secret),
		resp_master_salt, sizeof(resp_master_salt), resp_sender_id,
		sizeof(resp_sender_id), &resp_sender_id_len, resp_recipient_id,
		sizeof(resp_recipient_id), &resp_recipient_id_len));

	/* Both peers must derive the same OSCORE Master Secret and Master Salt,
	 * and each peer's Sender Id must equal the other's Recipient Id. */
	zassert_mem_equal(init_master_secret, resp_master_secret,
			  sizeof(init_master_secret),
			  "OSCORE master secret mismatch");
	zassert_mem_equal(init_master_salt, resp_master_salt,
			  sizeof(init_master_salt),
			  "OSCORE master salt mismatch");
	zassert_equal(init_sender_id_len, resp_recipient_id_len,
		      "sender / recipient id length mismatch");
	zassert_mem_equal(init_sender_id, resp_recipient_id, init_sender_id_len,
			  "sender / recipient id mismatch");
	zassert_equal(init_recipient_id_len, resp_sender_id_len,
		      "recipient / sender id length mismatch");
	zassert_mem_equal(init_recipient_id, resp_sender_id,
			  init_recipient_id_len,
			  "recipient / sender id mismatch");
}

static void benchmark_run_handshake(const struct benchmark_case *bench_case,
				    struct benchmark_result *result)
{
	const struct benchmark_endpoint initiator = {
		.connection_id = bench_case->initiator_connection_id,
		.own = bench_case->initiator,
		.peer = bench_case->responder,
		.ead = NULL,
	};
	const struct benchmark_endpoint responder = {
		.connection_id = bench_case->responder_connection_id,
		.own = bench_case->responder,
		.peer = bench_case->initiator,
		.ead = NULL,
	};

	uint8_t benchmark_message[BENCHMARK_MESSAGE_BUFFER_SIZE] = { 0 };
	struct edhoc_context benchmark_initiator = { 0 };
	struct edhoc_context benchmark_responder = { 0 };

	struct edhoc_context *const init_ctx = &benchmark_initiator;
	struct edhoc_context *const resp_ctx = &benchmark_responder;

	/* PSA is initialised and released per handshake so imported credential
	 * and ephemeral key slots never accumulate across iterations. Neither
	 * this nor context setup is part of the measured phases. */
	zassert_ok(psa_crypto_init());

	benchmark_setup_context(init_ctx, bench_case, &initiator);
	benchmark_setup_context(resp_ctx, bench_case, &responder);

	size_t message_length = 0;
	uint64_t total_ns = 0;
	uint64_t start = 0;

	/* --- Message 1 (Initiator -> Responder) --- */
	memset(benchmark_message, 0, sizeof(benchmark_message));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_1_COMPOSE,
			     edhoc_message_1_compose(init_ctx,
						     benchmark_message,
						     sizeof(benchmark_message),
						     &message_length));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_1_PROCESS,
			     edhoc_message_1_process(resp_ctx,
						     benchmark_message,
						     message_length));

	/* --- Message 2 (Responder -> Initiator) --- */
	memset(benchmark_message, 0, sizeof(benchmark_message));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_2_COMPOSE,
			     edhoc_message_2_compose(resp_ctx,
						     benchmark_message,
						     sizeof(benchmark_message),
						     &message_length));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_2_PROCESS,
			     edhoc_message_2_process(init_ctx,
						     benchmark_message,
						     message_length));

	/* --- Message 3 (Initiator -> Responder) --- */
	memset(benchmark_message, 0, sizeof(benchmark_message));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_3_COMPOSE,
			     edhoc_message_3_compose(init_ctx,
						     benchmark_message,
						     sizeof(benchmark_message),
						     &message_length));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_3_PROCESS,
			     edhoc_message_3_process(resp_ctx,
						     benchmark_message,
						     message_length));

	/* --- Message 4 (Responder -> Initiator) --- */
	memset(benchmark_message, 0, sizeof(benchmark_message));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_4_COMPOSE,
			     edhoc_message_4_compose(resp_ctx,
						     benchmark_message,
						     sizeof(benchmark_message),
						     &message_length));
	BENCHMARK_TIME_PHASE(BENCHMARK_PHASE_MESSAGE_4_PROCESS,
			     edhoc_message_4_process(init_ctx,
						     benchmark_message,
						     message_length));

	benchmark_result_add_total(result, total_ns);

	benchmark_assert_shared_secrets(init_ctx, resp_ctx);

	zassert_ok(edhoc_context_deinit(init_ctx));
	zassert_ok(edhoc_context_deinit(resp_ctx));

	mbedtls_psa_crypto_free();

	/* The post-quantum suite keeps credential keys in a software keystore
	 * the EDHOC context does not own; release them so slots do not
	 * accumulate across repeated handshakes (only built for that suite). */
#if defined(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
	if (EDHOC_CIPHER_SUITE_PQC_1 == bench_case->suite_id) {
		edhoc_cipher_suite_pqc_1_keystore_release_all();
	}
#endif
}

/* Module interface function definitions ----------------------------------- */

void benchmark_run_case(const struct benchmark_case *bench_case)
{
	struct benchmark_result result = { 0 };
	benchmark_result_init(&result, bench_case->name,
			      (int)bench_case->suite_id);

	for (size_t iteration = 0;
	     iteration < (size_t)CONFIG_EDHOC_BENCHMARK_ITERATIONS;
	     ++iteration) {
		benchmark_run_handshake(bench_case, &result);
	}

	benchmark_report_emit(&result);
}
