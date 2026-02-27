/**
 * \file    test_cipher_suites.c
 * \author  Kamil Kielbasa
 * \brief   Shared cipher suite definitions for tests.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 *
 */

/* Include files ----------------------------------------------------------- */

#include "test_cipher_suites.h"

const struct edhoc_cipher_suite test_cipher_suite_0 = {
	.value = 0,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 8,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

const struct edhoc_cipher_suite test_cipher_suite_2 = {
	.value = 2,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 32,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};
