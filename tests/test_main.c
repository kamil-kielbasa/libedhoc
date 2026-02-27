/**
 * \file    test_main.c
 * \author  Kamil Kielbasa
 * \brief   Test runner entry point for all libedhoc tests.
 *
 *          Tests are organized in a 3-tier architecture:
 *          - Unit tests:        Isolated function-level testing.
 *          - Integration tests: Full EDHOC handshake and protocol flows.
 *          - Fuzz tests:        Built separately (see fuzz/ directory).
 * \version 2.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 */

#include <unity.h>
#include <unity_fixture.h>

static void run_all_test_groups(void)
{
	/* ---- Unit tests ---- */
	RUN_TEST_GROUP(crypto_suite0);
	RUN_TEST_GROUP(crypto_suite2);
	RUN_TEST_GROUP(api);
	RUN_TEST_GROUP(api_negative);
	RUN_TEST_GROUP(error_message);
	RUN_TEST_GROUP(exporters);
	RUN_TEST_GROUP(helpers);
	RUN_TEST_GROUP(coverage);
	RUN_TEST_GROUP(internals);
	RUN_TEST_GROUP(message_paths);

	/* ---- Integration tests ---- */
	RUN_TEST_GROUP(rfc9529_chapter2);
	RUN_TEST_GROUP(rfc9529_chapter3);
	RUN_TEST_GROUP(rfc9528_negotiation);
	RUN_TEST_GROUP(handshake_x5chain_sig_suite0);
	RUN_TEST_GROUP(handshake_x5chain_sig_suite2);
	RUN_TEST_GROUP(handshake_x5chain_dh_suite2);
	RUN_TEST_GROUP(handshake_x5t_sig_suite2);
	RUN_TEST_GROUP(handshake_auth_methods);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, run_all_test_groups);
}
