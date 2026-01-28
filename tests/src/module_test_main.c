/**
 * \file    module_test_main.c
 * \author  Kamil Kielbasa
 * \brief   Module tests main.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Entry point for all module test groups.
 */
static void run_all_test_groups(void);

/* Static function definitions --------------------------------------------- */

static void run_all_test_groups(void)
{
	RUN_TEST_GROUP(cipher_suite_0);
	RUN_TEST_GROUP(cipher_suite_2);
	RUN_TEST_GROUP(rfc9529_chapter_2);
	RUN_TEST_GROUP(rfc9529_chapter_3);
	RUN_TEST_GROUP(rfc9528_suites_negotiation);
	RUN_TEST_GROUP(error_message);
	RUN_TEST_GROUP(x5chain_sign_keys_suite_0);
	RUN_TEST_GROUP(x5chain_sign_keys_suite_2);
	RUN_TEST_GROUP(x5chain_static_dh_keys_suite_2);
	RUN_TEST_GROUP(x5t_sign_keys_suite_2);
	RUN_TEST_GROUP(api);
	RUN_TEST_GROUP(edhoc_helpers);
}

/* Module interface function definitions ----------------------------------- */

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, run_all_test_groups);
}
