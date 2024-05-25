/**
 * \file    tests.c
 * \author  Kamil Kielbasa
 * \brief   Entry point for all unit tests.
 * \version 0.3
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
#include "x509_chain/test_edhoc_handshake_x5chain.h"
#include "edhoc_trace_2/test_edhoc_handshake_2.h"

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
	printf("test_edhoc_handshake_1_message_2_process:\n");
	test_edhoc_handshake_1_message_2_process();

	printf("\n");
	printf("test_edhoc_handshake_1_message_3_compose:\n");
	test_edhoc_handshake_1_message_3_compose();

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
	printf("test_edhoc_handshake_x5chain_e2e_real_crypto:\n");
	test_edhoc_handshake_x5chain_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_handshake_2_message_1_compose:\n");
	test_edhoc_handshake_2_message_1_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_1_process:\n");
	test_edhoc_handshake_2_message_1_process();

	printf("\n");
	printf("test_edhoc_handshake_1_message_2_compose:\n");
	test_edhoc_handshake_2_message_2_compose();

	printf("\n");
	printf("test_edhoc_handshake_2_message_2_process:\n");
	test_edhoc_handshake_2_message_2_process();

	printf("\n");
	printf("test_edhoc_handshake_2_message_3_compose:\n");
	test_edhoc_handshake_2_message_3_compose();

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

	printf("All tests passed successfully!\n");

	mbedtls_psa_crypto_free();

	return 0;
}
