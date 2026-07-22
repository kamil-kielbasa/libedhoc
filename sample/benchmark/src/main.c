/**
 * \file    main.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake benchmark for Zephyr / native_sim.
 *
 *          Runs a full EDHOC handshake with cipher suite 2 (P-256 / ES256),
 *          measures per-phase wall-clock timing via POSIX clock_gettime, and
 *          prints a JSON report to stdout.  The Zephyr build ensures the
 *          final linked binary reflects the real library flash/RAM footprint.
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
#include <assert.h>
#include <time.h>

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* Cipher suite 2 header: */
#include "edhoc_cipher_suite_2.h"

/* Test vector header: */
#include "test_vector_x5chain_sign_keys_suite_2.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */

#define MSG_BUF_SIZE ((size_t)512)
#define OSCORE_SECRET_LEN ((size_t)16)
#define OSCORE_SALT_LEN ((size_t)8)
#define OSCORE_ID_BUF_LEN ((size_t)8)

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
static void record_phase(struct bench_result *result, struct timespec start,
			 struct timespec end, double *total_iter_us);

static int cred_fetch_init(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred);
static int cred_fetch_resp(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred);
static int cred_verify_init(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len);
static int cred_verify_resp(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
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

static void print_json_report(size_t iterations,
			      const struct bench_result *results,
			      size_t num_phases, double total_sum_us,
			      double total_min_us, double total_max_us);

/* Static variables and constants ------------------------------------------ */

static const char *const phase_names[] = {
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

	const int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(0 == rc);
	(void)rc;

	return ts;
}

static double elapsed_us(const struct timespec start, const struct timespec end)
{
	const double sec = (double)(end.tv_sec - start.tv_sec);
	const double nsec = (double)(end.tv_nsec - start.tv_nsec);

	return sec * 1e6 + nsec / 1e3;
}

static void record_phase(struct bench_result *result,
			 const struct timespec start, const struct timespec end,
			 double *total_iter_us)
{
	const double us = elapsed_us(start, end);

	if (0 == result->count || us < result->min_us)
		result->min_us = us;

	if (us > result->max_us)
		result->max_us = us;

	result->sum_us += us;
	result->count++;
	*total_iter_us += us;
}

/* Import a raw P-256 scalar as an ECDSA (SIGN_HASH) private key handle. */
static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	if (PSA_SUCCESS != psa_import_key(&attr, priv, priv_len, &kid))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	memcpy(key_id, &kid, sizeof(kid));
	return EDHOC_SUCCESS;
}

static int cred_fetch_init(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.certificate[0] = CRED_I;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_I);

	return import_sign_priv_key(SK_I, ARRAY_SIZE(SK_I),
				    auth_cred->private_key_id);
}

static int cred_fetch_resp(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.certificate[0] = CRED_R;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_R);

	return import_sign_priv_key(SK_R, ARRAY_SIZE(SK_R),
				    auth_cred->private_key_id);
}

static int cred_verify_init(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_R))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_R, auth_cred->x509_chain.certificate[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int cred_verify_resp(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_I))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_I, auth_cred->x509_chain.certificate[0],
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

static void sample_zeroize(void *buffer, size_t length)
{
	volatile unsigned char *p = (volatile unsigned char *)buffer;

	while (0 != length--)
		*p++ = 0U;
}

static void setup_context(struct edhoc_context *ctx,
			  const struct edhoc_credentials *creds,
			  const bool is_initiator)
{
	int ret = edhoc_context_init(ctx);
	assert(EDHOC_SUCCESS == ret);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	ret = edhoc_set_methods(ctx, methods, ARRAY_SIZE(methods));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(ctx, edhoc_cipher_suite_2_get_suite(), 1);
	assert(EDHOC_SUCCESS == ret);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = is_initiator ? -14 : -24,
	};
	ret = edhoc_set_connection_id(ctx, &cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(ctx, edhoc_cipher_suite_2_get_crypto());
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(ctx, creds);
	assert(EDHOC_SUCCESS == ret);

	static const struct edhoc_ead ead = {
		.compose = ead_compose_stub,
		.process = ead_process_stub,
	};
	ret = edhoc_bind_ead(ctx, &ead);
	assert(EDHOC_SUCCESS == ret);

	static const struct edhoc_platform platform = {
		.zeroize = sample_zeroize,
	};
	ret = edhoc_bind_platform(ctx, &platform);
	assert(EDHOC_SUCCESS == ret);

	(void)ret;
}

static void print_json_report(const size_t iterations,
			      const struct bench_result *const results,
			      const size_t num_phases,
			      const double total_sum_us,
			      const double total_min_us,
			      const double total_max_us)
{
	printf("{\n");
	printf("  \"benchmark\": \"edhoc_handshake\",\n");
	printf("  \"cipher_suite\": 2,\n");
	printf("  \"method\": 0,\n");
	printf("  \"credentials\": \"x5chain\",\n");
	printf("  \"platform\": \"native_sim\",\n");
	printf("  \"iterations\": %zu,\n", iterations);
	printf("  \"phases\": {\n");

	for (size_t i = 0; i < num_phases; i++) {
		const double avg =
			(results[i].count > 0) ?
				results[i].sum_us / results[i].count :
				0.0;

		printf("    \"%s\": { \"avg_us\": %.1f, \"min_us\": %.1f, "
		       "\"max_us\": %.1f }%s\n",
		       phase_names[i], avg, results[i].min_us,
		       results[i].max_us, (i < num_phases - 1) ? "," : "");
	}

	const double avg_total = (iterations > 0) ? total_sum_us / iterations :
						    0.0;

	printf("  },\n");
	printf("  \"total_handshake\": { \"avg_us\": %.1f, \"min_us\": %.1f, "
	       "\"max_us\": %.1f }\n",
	       avg_total, total_min_us, total_max_us);
	printf("}\n");
}

/* Module interface function definitions ----------------------------------- */

int main(void)
{
	const size_t iterations = 10;

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

	const size_t num_phases = ARRAY_SIZE(phase_names);
	struct bench_result results[ARRAY_SIZE(phase_names)] = { 0 };

	double total_handshake_sum_us = 0.0;
	double total_handshake_min_us = 0.0;
	double total_handshake_max_us = 0.0;

	for (size_t iter = 0; iter < iterations; iter++) {
		struct edhoc_context *init_ctx = malloc(edhoc_context_size());

		assert(NULL != init_ctx);
		setup_context(init_ctx, &init_creds, true);

		struct edhoc_context *resp_ctx = malloc(edhoc_context_size());

		assert(NULL != resp_ctx);
		setup_context(resp_ctx, &resp_creds, false);

		size_t msg1_len = 0;
		uint8_t msg1[MSG_BUF_SIZE] = { 0 };

		size_t msg2_len = 0;
		uint8_t msg2[MSG_BUF_SIZE] = { 0 };

		size_t msg3_len = 0;
		uint8_t msg3[MSG_BUF_SIZE] = { 0 };

		size_t msg4_len = 0;
		uint8_t msg4[MSG_BUF_SIZE] = { 0 };

		int ret = EDHOC_ERROR_GENERIC_ERROR;

		struct timespec t0 = { 0 };
		struct timespec t1 = { 0 };
		size_t phase = 0;
		double total_iter_us = 0.0;

		/* Phase 0: msg1 compose (initiator). */
		t0 = clock_now();

		ret = edhoc_message_1_compose(init_ctx, msg1, sizeof(msg1),
					      &msg1_len);
		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 1: msg1 process + msg2 compose (responder). */
		t0 = clock_now();

		ret = edhoc_message_1_process(resp_ctx, msg1, msg1_len);

		if (EDHOC_SUCCESS == ret)
			ret = edhoc_message_2_compose(resp_ctx, msg2,
						      sizeof(msg2), &msg2_len);
		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 2: msg2 process + msg3 compose (initiator). */
		t0 = clock_now();

		ret = edhoc_message_2_process(init_ctx, msg2, msg2_len);

		if (EDHOC_SUCCESS == ret)
			ret = edhoc_message_3_compose(init_ctx, msg3,
						      sizeof(msg3), &msg3_len);

		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 3: msg3 process (responder). */
		t0 = clock_now();

		ret = edhoc_message_3_process(resp_ctx, msg3, msg3_len);

		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 4: msg4 compose (responder). */
		t0 = clock_now();

		ret = edhoc_message_4_compose(resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);

		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 5: msg4 process (initiator). */
		t0 = clock_now();

		ret = edhoc_message_4_process(init_ctx, msg4, msg4_len);

		t1 = clock_now();

		if (EDHOC_SUCCESS != ret)
			goto cleanup;

		record_phase(&results[phase], t0, t1, &total_iter_us);
		phase++;

		/* Phase 6: OSCORE session export (both sides).  Both contexts
		 * must agree on master secret / salt; the connection-id roles
		 * are swapped between peers (initiator's Sender ID equals the
		 * responder's Recipient ID and vice versa). */
		{
			uint8_t init_secret[OSCORE_SECRET_LEN] = { 0 };
			uint8_t init_salt[OSCORE_SALT_LEN] = { 0 };
			uint8_t init_sid[OSCORE_ID_BUF_LEN] = { 0 };
			uint8_t init_rid[OSCORE_ID_BUF_LEN] = { 0 };
			size_t init_sid_len = 0;
			size_t init_rid_len = 0;

			uint8_t resp_secret[OSCORE_SECRET_LEN] = { 0 };
			uint8_t resp_salt[OSCORE_SALT_LEN] = { 0 };
			uint8_t resp_sid[OSCORE_ID_BUF_LEN] = { 0 };
			uint8_t resp_rid[OSCORE_ID_BUF_LEN] = { 0 };
			size_t resp_sid_len = 0;
			size_t resp_rid_len = 0;

			t0 = clock_now();

			ret = edhoc_export_oscore_session_raw(
				init_ctx, init_secret, OSCORE_SECRET_LEN,
				init_salt, OSCORE_SALT_LEN, init_sid,
				sizeof(init_sid), &init_sid_len, init_rid,
				sizeof(init_rid), &init_rid_len);

			if (EDHOC_SUCCESS == ret) {
				ret = edhoc_export_oscore_session_raw(
					resp_ctx, resp_secret,
					OSCORE_SECRET_LEN, resp_salt,
					OSCORE_SALT_LEN, resp_sid,
					sizeof(resp_sid), &resp_sid_len,
					resp_rid, sizeof(resp_rid),
					&resp_rid_len);
			}

			t1 = clock_now();

			if (EDHOC_SUCCESS != ret)
				goto cleanup;

			assert(0 == memcmp(init_secret, resp_secret,
					   OSCORE_SECRET_LEN));
			assert(0 ==
			       memcmp(init_salt, resp_salt, OSCORE_SALT_LEN));
			assert(init_sid_len == resp_rid_len);
			assert(0 == memcmp(init_sid, resp_rid, init_sid_len));
			assert(init_rid_len == resp_sid_len);
			assert(0 == memcmp(init_rid, resp_sid, init_rid_len));

			record_phase(&results[phase], t0, t1, &total_iter_us);
		}

		total_handshake_sum_us += total_iter_us;

		if (0 == iter || total_iter_us < total_handshake_min_us)
			total_handshake_min_us = total_iter_us;

		if (total_iter_us > total_handshake_max_us)
			total_handshake_max_us = total_iter_us;

cleanup:
		edhoc_context_deinit(init_ctx);
		edhoc_context_deinit(resp_ctx);
		free(init_ctx);
		free(resp_ctx);

		if (EDHOC_SUCCESS != ret) {
			printf("Handshake failed at iter %zu phase %zu: %d\n",
			       iter, phase, ret);
			return 1;
		}
	}

	print_json_report(iterations, results, num_phases,
			  total_handshake_sum_us, total_handshake_min_us,
			  total_handshake_max_us);

	exit(0);
}
