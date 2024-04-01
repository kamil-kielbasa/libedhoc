/**
 * @file    tests.c
 * @author  Kamil Kielbasa
 * @brief   Main file for unit tests.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_mbedtls_crypto.h"
#include "test_edhoc_exporter.h"
#include "test_edhoc_x509_chain.h"
#include "test_edhoc_x509_hash.h"
#include "test_edhoc_x509_kid.h"
#include "test_edhoc_ead.h"

/* Standard library header: */
#include <stdio.h>

/* Crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

#include "test_crypto.h"

int main(void)
{
	if (PSA_SUCCESS != psa_crypto_init()) {
		printf("psa crypto init error!\n");
		return -1;
	}

	printf("\n");
	printf("test_mbedtls_crypto_aead:\n");
	test_mbedtls_crypto_aead();

	printf("\n");
	printf("test_mbedtls_crypto_ecdsa:\n");
	test_mbedtls_crypto_ecdsa();

	printf("\n");
	printf("test_mbedtls_crypto_ecdh:\n");
	test_mbedtls_crypto_ecdh();

	printf("\n");
	printf("test_mbedtls_crypto_hkdf:\n");
	test_mbedtls_crypto_hkdf();

	printf("\n");
	printf("test_mbedtls_crypto_hash:\n");
	test_mbedtls_crypto_hash();

	printf("\n");
	printf("test_edhoc_exporter:\n");
	test_edhoc_exporter();

	printf("\n");
	printf("test_edhoc_x509_chain_message_1_compose:\n");
	test_edhoc_x509_chain_message_1_compose();

	printf("\n");
	printf("test_edhoc_x509_chain_message_1_process:\n");
	test_edhoc_x509_chain_message_1_process();

	printf("\n");
	printf("test_edhoc_x509_chain_message_2_compose:\n");
	test_edhoc_x509_chain_message_2_compose();

	printf("\n");
	printf("test_edhoc_x509_chain_message_2_process:\n");
	test_edhoc_x509_chain_message_2_process();

	printf("\n");
	printf("test_edhoc_x509_chain_message_3_compose:\n");
	test_edhoc_x509_chain_message_3_compose();

	printf("\n");
	printf("test_edhoc_x509_chain_message_3_process:\n");
	test_edhoc_x509_chain_message_3_process();

	printf("\n");
	printf("test_edhoc_x509_chain_edhoc_e2e:\n");
	test_edhoc_x509_chain_edhoc_e2e();

	printf("\n");
	printf("test_edhoc_x509_chain_edhoc_e2e_real_crypto:\n");
	test_edhoc_x509_chain_edhoc_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_x509_hash_message_1_compose:\n");
	test_edhoc_x509_hash_message_1_compose();

	printf("\n");
	printf("test_edhoc_x509_hash_message_1_process:\n");
	test_edhoc_x509_hash_message_1_process();

	printf("\n");
	printf("test_edhoc_x509_hash_message_2_compose:\n");
	test_edhoc_x509_hash_message_2_compose();

	printf("\n");
	printf("test_edhoc_x509_hash_message_2_process:\n");
	test_edhoc_x509_hash_message_2_process();

	printf("\n");
	printf("test_edhoc_x509_hash_message_3_compose:\n");
	test_edhoc_x509_hash_message_3_compose();

	printf("\n");
	printf("test_edhoc_x509_hash_message_3_process:\n");
	test_edhoc_x509_hash_message_3_process();

	printf("\n");
	printf("test_edhoc_x509_hash_edhoc_e2e:\n");
	test_edhoc_x509_hash_edhoc_e2e();

	printf("\n");
	printf("test_edhoc_x509_hash_edhoc_e2e_real_crypto:\n");
	test_edhoc_x509_hash_edhoc_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_x509_kid_message_1_compose:\n");
	test_edhoc_x509_kid_message_1_compose();

	printf("\n");
	printf("test_edhoc_x509_kid_message_1_process:\n");
	test_edhoc_x509_kid_message_1_process();

	printf("\n");
	printf("test_edhoc_x509_kid_message_2_compose:\n");
	test_edhoc_x509_kid_message_2_compose();

	printf("\n");
	printf("test_edhoc_x509_kid_message_2_process:\n");
	test_edhoc_x509_kid_message_2_process();

	printf("\n");
	printf("test_edhoc_x509_kid_message_3_compose:\n");
	test_edhoc_x509_kid_message_3_compose();

	printf("\n");
	printf("test_edhoc_x509_kid_message_3_process:\n");
	test_edhoc_x509_kid_message_3_process();

	printf("\n");
	printf("test_edhoc_x509_kid_edhoc_e2e:\n");
	test_edhoc_x509_kid_edhoc_e2e();

	printf("\n");
	printf("test_edhoc_x509_kid_edhoc_e2e_real_crypto:\n");
	test_edhoc_x509_kid_edhoc_e2e_real_crypto();

	printf("\n");
	printf("test_edhoc_single_ead_token:\n");
	test_edhoc_single_ead_token();

	printf("\n");
	printf("test_edhoc_multiple_ead_tokens:\n");
	test_edhoc_multiple_ead_tokens();

	mbedtls_psa_crypto_free();

	return 0;
}