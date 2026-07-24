/**
 * \file    test_main.c
 * \author  Kamil Kielbasa
 * \brief   Transitional runner for the not-yet-migrated unit tests.
 *
 *          The cipher-suite, integration and RFC 9529 tests now live under
 *          tests/linux/ as standalone per-suite/per-scenario binaries. What
 *          remains here is the unit tier, which is cross-suite (test_api binds
 *          suites 0/2/24 together) and is migrated in its own PR to a
 *          suite-agnostic form. Until then this binary builds only under the
 *          transitional `legacy` preset (all suites enabled).
 *
 * \copyright Copyright (c) 2026
 */

#include <unity.h>
#include <unity_fixture.h>

#include "edhoc_backend_memory.h"

static void run_all_test_groups(void)
{
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
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, run_all_test_groups);
}
