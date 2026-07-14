/**
 * \file    test_main.c
 * \author  Kamil Kielbasa
 * \brief   Test runner entry point for all libedhoc tests.
 *
 *          Tests are organized in a 3-tier architecture:
 *          - Unit tests:        Isolated function-level testing.
 *          - Integration tests: Full EDHOC handshake and protocol flows.
 *          - Fuzz tests:        Built separately (see fuzz/ directory).
 *
 * \copyright Copyright (c) 2025
 */

#include <unity.h>
#include <unity_fixture.h>

#include "edhoc_backend_memory.h"

static void run_all_test_groups(void)
{
	/* ---- Unit tests ---- */
	RUN_TEST_GROUP(cipher_suite_0_positive);
	RUN_TEST_GROUP(cipher_suite_0_negative);
	RUN_TEST_GROUP(cipher_suite_2_positive);
	RUN_TEST_GROUP(cipher_suite_2_negative);
	RUN_TEST_GROUP(cipher_suite_4);
	RUN_TEST_GROUP(cipher_suite_24);
#ifdef LIBEDHOC_ENABLE_EXPERIMENTAL_PQC
	RUN_TEST_GROUP(cipher_suite_exp_pqc_1);
#endif
	RUN_TEST_GROUP(api);
	RUN_TEST_GROUP(api_negative);
	RUN_TEST_GROUP(error_message);
	RUN_TEST_GROUP(exporters);
	RUN_TEST_GROUP(coap);
	RUN_TEST_GROUP(coverage_msg1);
	RUN_TEST_GROUP(coverage_msg2);
	RUN_TEST_GROUP(coverage_msg3);
	RUN_TEST_GROUP(coverage_msg4);
	RUN_TEST_GROUP(coverage_exporters);
	RUN_TEST_GROUP(coverage_error);
	RUN_TEST_GROUP(coverage_cbor);
	RUN_TEST_GROUP(coverage_handshake);
	RUN_TEST_GROUP(coverage_sweep_validate);
	RUN_TEST_GROUP(internals_common);
	RUN_TEST_GROUP(internals_mac);
	RUN_TEST_GROUP(internals_message2);
	RUN_TEST_GROUP(internals_message3);
	RUN_TEST_GROUP(internals_message4);
	RUN_TEST_GROUP(internals_error);
	RUN_TEST_GROUP(internals_message1);
	RUN_TEST_GROUP(internals_coap);
	RUN_TEST_GROUP(internals_api);
	RUN_TEST_GROUP(message_paths);
#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM
	RUN_TEST_GROUP(mem_custom);
#endif

	/* ---- Integration tests ---- */
	RUN_TEST_GROUP(rfc9529_chapter2);
	RUN_TEST_GROUP(rfc9529_chapter3);
	RUN_TEST_GROUP(rfc9528_negotiation);
	RUN_TEST_GROUP(handshake_x5chain_sig_suite0);
	RUN_TEST_GROUP(handshake_x5chain_sig_suite2);
	RUN_TEST_GROUP(handshake_x5chain_sig_suite24);
	RUN_TEST_GROUP(handshake_x5chain_dh_suite2);
	RUN_TEST_GROUP(handshake_x5t_sig_suite2);
	RUN_TEST_GROUP(handshake_auth_methods);
#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM
	RUN_TEST_GROUP(mem_custom_handshake);
#endif
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, run_all_test_groups);
}
