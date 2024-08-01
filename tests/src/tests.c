/**
 * \file    tests.c
 * \author  Kamil Kielbasa
 * \brief   Entry point for all unit tests.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "cipher_suites/test_cipher_suite_0.h"
#include "cipher_suites/test_cipher_suite_2.h"
#include "edhoc_trace_1/test_edhoc_handshake_1.h"
#include "edhoc_trace_1/test_edhoc_handshake_ead_1.h"
#include "x509_chain_cs_0/test_edhoc_handshake_x5chain_cs_0.h"
#include "x509_chain_cs_2/test_edhoc_handshake_x5chain_cs_2.h"
#include "x509_chain_cs_2/test_edhoc_handshake_x5chain_cs_2_ead.h"
#include "x509_chain_cs_2_static_dh/test_edhoc_handshake_x5chain_cs_2_static_dh_ead.h"
#include "x509_hash_cs_2/test_edhoc_handshake_x5t_cs_2_ead.h"
#include "edhoc_trace_2/test_edhoc_handshake_2.h"
#include "error_message/test_edhoc_error_message.h"
#include "cipher_suite_negotiation/test_edhoc_cipher_suite_negotiation.h"

/* Standard library headers:*/
#include <stdio.h>
#include <assert.h>

/* Crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int main(void)
{
	/*
	 * Unit tests for cipher suites.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_cipher_suite_0_ecdsa:\n");
	test_cipher_suite_0_ecdsa();

	printf("\n");
	printf("test_cipher_suite_0_ecdh:\n");
	test_cipher_suite_0_ecdh();

	printf("\n");
	printf("test_cipher_suite_0_hkdf:\n");
	test_cipher_suite_0_hkdf();

	printf("\n");
	printf("test_cipher_suite_0_aead:\n");
	test_cipher_suite_0_aead();

	printf("\n");
	printf("test_cipher_suite_2_ecdsa:\n");
	test_cipher_suite_2_ecdsa();

	printf("\n");
	printf("test_cipher_suite_2_ecdh:\n");
	test_cipher_suite_2_ecdh();

	printf("\n");
	printf("test_cipher_suite_2_hkdf:\n");
	test_cipher_suite_2_hkdf();

	printf("\n");
	printf("test_cipher_suite_2_aead:\n");
	test_cipher_suite_2_aead();

	mbedtls_psa_crypto_free();

	/*
	 * Unit tests for EDHOC trace 1.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_edhoc_handshake_1_message_1_compose:\n");
	test_edhoc_handshake_1_message_1_compose();

	printf("\n");
	printf("test_edhoc_handshake_1_message_1_process:\n");
	test_edhoc_handshake_1_message_1_process();

	printf("\n");
	printf("test_edhoc_handshake_1_message_2_compose:\n");
	test_edhoc_handshake_1_message_2_compose();

	printf("\n");
	printf("test_edhoc_handshake_any_1_message_2_compose:\n");
	test_edhoc_handshake_any_1_message_2_compose();

	printf("\n");
	printf("test_edhoc_handshake_1_message_2_process:\n");
	test_edhoc_handshake_1_message_2_process();

	printf("\n");
	printf("test_edhoc_handshake_1_message_3_compose:\n");
	test_edhoc_handshake_1_message_3_compose();

	printf("\n");
	printf("test_edhoc_handshake_any_1_message_3_compose:\n");
	test_edhoc_handshake_any_1_message_3_compose();

	printf("\n");
	printf("test_edhoc_handshake_1_message_3_process:\n");
	test_edhoc_handshake_1_message_3_process();

	printf("\n");
	printf("test_edhoc_handshake_1_message_4_compose:\n");
	test_edhoc_handshake_1_message_4_compose();

	printf("\n");
	printf("test_edhoc_handshake_1_message_4_process:\n");
	test_edhoc_handshake_1_message_4_process();

	printf("\n");
	printf("test_edhoc_handshake_1_e2e:\n");
	test_edhoc_handshake_1_e2e();

	printf("\n");
	printf("test_edhoc_handshake_1_e2e_real_crypto:\n");
	test_edhoc_handshake_1_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_handshake_1_e2e_single_ead_token:\n");
	test_edhoc_handshake_1_e2e_single_ead_token();

	printf("\n");
	printf("test_edhoc_handshake_1_e2e_multiple_ead_tokens:\n");
	test_edhoc_handshake_1_e2e_multiple_ead_tokens();

	printf("\n");
	printf("test_edhoc_handshake_x5chain_cs_0_single_cert_e2e_real_crypto:\n");
	test_edhoc_handshake_x5chain_cs_0_single_cert_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_handshake_x5chain_cs_0_many_certs_e2e_real_crypto:\n");
	test_edhoc_handshake_x5chain_cs_0_many_certs_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_handshake_x5chain_cs_2_single_cert_e2e:\n");
	test_edhoc_handshake_x5chain_cs_2_single_cert_e2e();

	printf("\n");
	printf("test_edhoc_handshake_x5chain_cs_2_single_cert_e2e_multiple_ead_tokens:\n");
	test_edhoc_handshake_x5chain_cs_2_single_cert_e2e_multiple_ead_tokens();

	printf("\n");
	printf("test_edhoc_handshake_x5chain_cs_2_static_dh_keys_ead_e2e:\n");
	test_edhoc_handshake_x5chain_cs_2_static_dh_keys_ead_e2e();

	printf("\n");
	printf("test_edhoc_handshake_x5t_cs_2_e2e_single_ead_token:\n");
	test_edhoc_handshake_x5t_cs_2_e2e_single_ead_token();

	mbedtls_psa_crypto_free();

	/*
	 * Unit tests for EDHOC trace 2.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_edhoc_handshake_2_message_1_compose:\n");
	test_edhoc_handshake_2_message_1_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_1_process:\n");
	test_edhoc_handshake_2_message_1_process();

	printf("\n");
	printf("test_edhoc_handshake_2_message_2_compose:\n");
	test_edhoc_handshake_2_message_2_compose();

	printf("\n");
	printf("test_edhoc_handshake_any_2_message_2_compose:\n");
	test_edhoc_handshake_any_2_message_2_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_2_process:\n");
	test_edhoc_handshake_2_message_2_process();

	printf("\n");
	printf("test_edhoc_handshake_2_message_3_compose:\n");
	test_edhoc_handshake_2_message_3_compose();

	printf("\n");
	printf("test_edhoc_handshake_any_2_message_3_compose:\n");
	test_edhoc_handshake_any_2_message_3_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_3_process:\n");
	test_edhoc_handshake_2_message_3_process();

	printf("\n");
	printf("test_edhoc_handshake_2_message_4_compose:\n");
	test_edhoc_handshake_2_message_4_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_4_process:\n");
	test_edhoc_handshake_2_message_4_process();

	printf("\n");
	printf("test_edhoc_handshake_2_e2e:\n");
	test_edhoc_handshake_2_e2e();

	printf("\n");
	printf("test_edhoc_handshake_2_e2e_real_crypto:\n");
	test_edhoc_handshake_2_e2e_real_crypto();

	mbedtls_psa_crypto_free();

	/*
	 * Unit tests for EDHOC error message.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_edhoc_error_message_success:\n");
	test_edhoc_error_message_success();

	printf("\n");
	printf("test_edhoc_error_message_unspecified_error:\n");
	test_edhoc_error_message_unspecified_error();

	printf("\n");
	printf("test_edhoc_error_message_wrong_selected_cipher_suite_one:\n");
	test_edhoc_error_message_wrong_selected_cipher_suite_one();

	printf("\n");
	printf("test_edhoc_error_message_wrong_selected_cipher_suite_many:\n");
	test_edhoc_error_message_wrong_selected_cipher_suite_many();

	printf("\n");
	printf("test_edhoc_error_message_unknown_credential_referenced:\n");
	test_edhoc_error_message_unknown_credential_referenced();

	mbedtls_psa_crypto_free();

	/*
	 * Unit tests for EDHOC PRK exporter.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_edhoc_trace_1_prk_exporter:\n");
	test_edhoc_trace_1_prk_exporter();

	mbedtls_psa_crypto_free();

	/*
	 * Unit tests for EDHOC cipher suite negotiation.
	 */
	assert(PSA_SUCCESS == psa_crypto_init());

	printf("\n");
	printf("test_edhoc_cipher_suites_negotiation_scenario_1:\n");
	test_edhoc_cipher_suites_negotiation_scenario_1();

	printf("\n");
	printf("test_edhoc_cipher_suites_negotiation_scenario_2:\n");
	test_edhoc_cipher_suites_negotiation_scenario_2();

	mbedtls_psa_crypto_free();

	printf("All tests passed successfully!\n");
	return 0;
}
