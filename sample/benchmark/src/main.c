/**
 * \file    main.c
 * \author  libedhoc
 * \brief   EDHOC handshake benchmark for Zephyr / native_sim.
 *
 *          Runs a full EDHOC handshake with cipher suite 2 (P-256 / ES256),
 *          measures per-phase wall-clock timing via POSIX clock_gettime, and
 *          prints a JSON report to stdout.  The Zephyr build ensures the
 *          final linked binary reflects the real library flash/RAM footprint.
 *
 * \version 1.0
 * \date    2026-02-27
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <float.h>
#include <time.h>

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* Cipher suite 2 header: */
#include "edhoc_cipher_suite_2.h"

/* Test vector header: */
#include "test_vector_x5chain_sign_keys_suite_2.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */

#define MSG_BUF_SIZE      ((size_t)512)
#define OSCORE_SECRET_LEN ((size_t)16)
#define OSCORE_SALT_LEN   ((size_t)8)
#define BENCH_ITERATIONS  ((size_t)10)
#define NUM_PHASES        ((size_t)7)

/* Module types and type definitiones -------------------------------------- */

struct bench_result {
	double min_us;
	double max_us;
	double sum_us;
	size_t count;
};

/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

static struct timespec clock_now(void);
static double elapsed_us(struct timespec start, struct timespec end);
static void record_phase(struct bench_result *r, struct timespec start,
			 struct timespec end, double *total_iter_us);

static int cred_fetch_init(void *user_ctx,
			   struct edhoc_auth_creds *auth_cred);
static int cred_fetch_resp(void *user_ctx,
			   struct edhoc_auth_creds *auth_cred);
static int cred_verify_init(void *user_ctx,
			    struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len);
static int cred_verify_resp(void *user_ctx,
			    struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len);

static int ead_compose_stub(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len);
static int ead_process_stub(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size);

static void setup_context(struct edhoc_context *ctx,
			  const struct edhoc_credentials *creds,
			  bool is_initiator);

/* Static variables and constants ------------------------------------------ */

static const char *const phase_names[NUM_PHASES] = {
	"msg1_compose",
	"msg1_process_msg2_compose",
	"msg2_process_msg3_compose",
	"msg3_process",
	"msg4_compose",
	"msg4_process",
	"oscore_export",
};

/* Static function definitions --------------------------------------------- */

static struct timespec clock_now(void)
{
	struct timespec ts = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts;
}

static double elapsed_us(const struct timespec start,
			 const struct timespec end)
{
	const double sec = (double)(end.tv_sec - start.tv_sec);
	const double nsec = (double)(end.tv_nsec - start.tv_nsec);

	return sec * 1e6 + nsec / 1e3;
}

static void record_phase(struct bench_result *r, const struct timespec start,
			 const struct timespec end, double *total_iter_us)
{
	const double us = elapsed_us(start, end);

	r->sum_us += us;

	if (us < r->min_us)
		r->min_us = us;

	if (us > r->max_us)
		r->max_us = us;

	r->count++;
	*total_iter_us += us;
}

static int cred_fetch_init(void *user_ctx,
			   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_I;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_I);

	return edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE,
					       SK_I, ARRAY_SIZE(SK_I),
					       auth_cred->priv_key_id);
}

static int cred_fetch_resp(void *user_ctx,
			   struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_R;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_R);

	return edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE,
					       SK_R, ARRAY_SIZE(SK_R),
					       auth_cred->priv_key_id);
}

static int cred_verify_init(void *user_ctx,
			    struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_R))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_R, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int cred_verify_resp(void *user_ctx,
			    struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_I))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_I, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

static int ead_compose_stub(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;

	*ead_token_len = 0;

	return EDHOC_SUCCESS;
}

static int ead_process_stub(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)ead_token;
	(void)ead_token_size;

	return EDHOC_SUCCESS;
}

static void setup_context(struct edhoc_context *ctx,
			  const struct edhoc_credentials *creds,
			  const bool is_initiator)
{
	edhoc_context_init(ctx);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(ctx, methods, 1);

	const struct edhoc_cipher_suite csuite = {
		.value = 2,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 32,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	};
	edhoc_set_cipher_suites(ctx, &csuite, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = is_initiator ? -14 : -24,
	};
	edhoc_set_connection_id(ctx, &cid);

	edhoc_bind_keys(ctx, edhoc_cipher_suite_2_get_keys());
	edhoc_bind_crypto(ctx, edhoc_cipher_suite_2_get_crypto());
	edhoc_bind_credentials(ctx, creds);

	static const struct edhoc_ead ead = {
		.compose = ead_compose_stub,
		.process = ead_process_stub,
	};
	edhoc_bind_ead(ctx, &ead);
}

/* Module interface function definitions ----------------------------------- */

int main(void)
{
	const size_t iterations = BENCH_ITERATIONS;

	const psa_status_t status = psa_crypto_init();
	if (PSA_SUCCESS != status) {
		printf("psa_crypto_init failed: %d\n", (int)status);
		return 1;
	}

	const struct edhoc_credentials init_creds = {
		.fetch = cred_fetch_init,
		.verify = cred_verify_init,
	};
	const struct edhoc_credentials resp_creds = {
		.fetch = cred_fetch_resp,
		.verify = cred_verify_resp,
	};

	struct bench_result results[NUM_PHASES] = { 0 };
	for (size_t i = 0; i < NUM_PHASES; i++) {
		results[i].min_us = DBL_MAX;
		results[i].max_us = 0.0;
		results[i].sum_us = 0.0;
		results[i].count = 0;
	}

	double total_handshake_sum_us = 0.0;
	double total_handshake_min_us = DBL_MAX;
	double total_handshake_max_us = 0.0;

	for (size_t iter = 0; iter < iterations; iter++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		setup_context(&init_ctx, &init_creds, true);
		setup_context(&resp_ctx, &resp_creds, false);

		uint8_t msg1[MSG_BUF_SIZE] = { 0 };
		uint8_t msg2[MSG_BUF_SIZE] = { 0 };
		uint8_t msg3[MSG_BUF_SIZE] = { 0 };
		uint8_t msg4[MSG_BUF_SIZE] = { 0 };
		size_t msg1_len = 0;
		size_t msg2_len = 0;
		size_t msg3_len = 0;
		size_t msg4_len = 0;
		int ret = EDHOC_ERROR_GENERIC_ERROR;
		struct timespec t0 = { 0 };
		struct timespec t1 = { 0 };
		size_t phase = 0;
		double total_iter_us = 0.0;

		/* Phase 0: msg1 compose (initiator). */
		t0 = clock_now();
		ret = edhoc_message_1_compose(&init_ctx, msg1,
					      sizeof(msg1), &msg1_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 1: msg1 process + msg2 compose (responder). */
		t0 = clock_now();
		ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
		if (EDHOC_SUCCESS == ret)
			ret = edhoc_message_2_compose(&resp_ctx, msg2,
						      sizeof(msg2), &msg2_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 2: msg2 process + msg3 compose (initiator). */
		t0 = clock_now();
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		if (EDHOC_SUCCESS == ret)
			ret = edhoc_message_3_compose(&init_ctx, msg3,
						      sizeof(msg3), &msg3_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 3: msg3 process (responder). */
		t0 = clock_now();
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 4: msg4 compose (responder). */
		t0 = clock_now();
		ret = edhoc_message_4_compose(&resp_ctx, msg4,
					      sizeof(msg4), &msg4_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 5: msg4 process (initiator). */
		t0 = clock_now();
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		t1 = clock_now();
		if (EDHOC_SUCCESS != ret)
			goto cleanup;
		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 6: OSCORE session export (both sides). */
		{
			uint8_t secret[OSCORE_SECRET_LEN] = { 0 };
			uint8_t salt[OSCORE_SALT_LEN] = { 0 };
			uint8_t sid[8] = { 0 };
			uint8_t rid[8] = { 0 };
			size_t sid_len = 0;
			size_t rid_len = 0;

			t0 = clock_now();
			ret = edhoc_export_oscore_session(
				&init_ctx,
				secret, OSCORE_SECRET_LEN,
				salt, OSCORE_SALT_LEN,
				sid, sizeof(sid), &sid_len,
				rid, sizeof(rid), &rid_len);
			if (EDHOC_SUCCESS == ret)
				ret = edhoc_export_oscore_session(
					&resp_ctx,
					secret, OSCORE_SECRET_LEN,
					salt, OSCORE_SALT_LEN,
					sid, sizeof(sid), &sid_len,
					rid, sizeof(rid), &rid_len);
			t1 = clock_now();
			if (EDHOC_SUCCESS != ret)
				goto cleanup;
			record_phase(&results[phase], t0, t1, &total_iter_us);
		}

		total_handshake_sum_us += total_iter_us;

		if (total_iter_us < total_handshake_min_us)
			total_handshake_min_us = total_iter_us;

		if (total_iter_us > total_handshake_max_us)
			total_handshake_max_us = total_iter_us;

cleanup:
		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);

		if (EDHOC_SUCCESS != ret) {
			printf("Handshake failed at iter %zu phase %zu: %d\n",
			       iter, phase, ret);
			return 1;
		}
	}

	/* Print JSON benchmark report. */
	printf("{\n");
	printf("  \"benchmark\": \"edhoc_handshake\",\n");
	printf("  \"cipher_suite\": 2,\n");
	printf("  \"method\": 0,\n");
	printf("  \"credentials\": \"x5chain\",\n");
	printf("  \"platform\": \"native_sim\",\n");
	printf("  \"iterations\": %zu,\n", iterations);
	printf("  \"phases\": {\n");

	for (size_t i = 0; i < NUM_PHASES; i++) {
		const double avg = (results[i].count > 0)
				   ? results[i].sum_us / results[i].count
				   : 0.0;

		printf("    \"%s\": { \"avg_us\": %.1f, \"min_us\": %.1f, "
		       "\"max_us\": %.1f }%s\n",
		       phase_names[i], avg, results[i].min_us,
		       results[i].max_us,
		       (i < NUM_PHASES - 1) ? "," : "");
	}

	const double avg_total = (iterations > 0)
				 ? total_handshake_sum_us / iterations
				 : 0.0;

	printf("  },\n");
	printf("  \"total_handshake\": { \"avg_us\": %.1f, \"min_us\": %.1f, "
	       "\"max_us\": %.1f }\n",
	       avg_total, total_handshake_min_us, total_handshake_max_us);
	printf("}\n");

	exit(0);
}
