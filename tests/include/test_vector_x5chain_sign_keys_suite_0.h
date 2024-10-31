/**
 * \file    test_vector_x5chain_sign_keys_suite_0.h
 * \author  Kamil Kielbasa
 * \brief   Test vector with keys and certificates for Ed25519 & X25519 curve.
 * \version 0.6
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_VECTOR_X5CHAIN_SIGN_KEYS_SUITE_0_H
#define TEST_VECTOR_X5CHAIN_SIGN_KEYS_SUITE_0_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

/**
 * \brief EDHOC message 1.
 */

static const uint8_t METHOD = 0;

static const int32_t SUITES_I[] = { 0 };

static const uint8_t C_I[] = { -14 };

/**
 * \brief EDHOC message 2.
 */

static const uint8_t SUITES_R[] = { 0 };

static const uint8_t C_R[] = { 24 };

static const uint8_t SK_R[] = {
	0xef, 0x14, 0x0f, 0xf9, 0x00, 0xb0, 0xab, 0x03, 0xf0, 0xc0, 0x8d,
	0x87, 0x9c, 0xbb, 0xd4, 0xb3, 0x1e, 0xa7, 0x1e, 0x6e, 0x7e, 0xe7,
	0xff, 0xcb, 0x7e, 0x79, 0x55, 0x77, 0x7a, 0x33, 0x27, 0x99,

	0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c,
	0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6,
	0x62, 0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
};

static const uint8_t PK_R[] = {
	0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c,
	0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6,
	0x62, 0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
};

static const uint8_t CRED_R[] = {
	0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
	0x04, 0x62, 0x31, 0x9e, 0xc4, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
	0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
	0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32,
	0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x33, 0x36, 0x5a,
	0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30,
	0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x21, 0x00, 0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1,
	0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2,
	0xc6, 0x62, 0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xb7, 0x23, 0xbc,
	0x01, 0xea, 0xb0, 0x92, 0x8e, 0x8b, 0x2b, 0x6c, 0x98, 0xde, 0x19, 0xcc,
	0x38, 0x23, 0xd4, 0x6e, 0x7d, 0x69, 0x87, 0xb0, 0x32, 0x47, 0x8f, 0xec,
	0xfa, 0xf1, 0x45, 0x37, 0xa1, 0xaf, 0x14, 0xcc, 0x8b, 0xe8, 0x29, 0xc6,
	0xb7, 0x30, 0x44, 0x10, 0x18, 0x37, 0xeb, 0x4a, 0xbc, 0x94, 0x95, 0x65,
	0xd8, 0x6d, 0xce, 0x51, 0xcf, 0xae, 0x52, 0xab, 0x82, 0xc1, 0x52, 0xcb,
	0x02,
};

/**
 * \brief EDHOC message 3.
 */

static const uint8_t SK_I[] = {
	0x4c, 0x5b, 0x25, 0x87, 0x8f, 0x50, 0x7c, 0x6b, 0x9d, 0xae, 0x68,
	0xfb, 0xd4, 0xfd, 0x3f, 0xf9, 0x97, 0x53, 0x3d, 0xb0, 0xaf, 0x00,
	0xb2, 0x5d, 0x32, 0x4e, 0xa2, 0x8e, 0x6c, 0x21, 0x3b, 0xc8,

	0xed, 0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f, 0xa5, 0x45,
	0x25, 0xc9, 0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4, 0x3e,
	0x0f, 0x23, 0xd8, 0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14, 0x1e,
};

static const uint8_t PK_I[] = {
	0xed, 0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f, 0xa5, 0x45,
	0x25, 0xc9, 0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4, 0x3e,
	0x0f, 0x23, 0xd8, 0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14, 0x1e,
};

static const uint8_t CRED_I[] = {
	0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
	0x04, 0x62, 0x31, 0x9e, 0xa0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
	0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
	0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32,
	0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x30, 0x30, 0x5a,
	0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30,
	0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e,
	0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x21, 0x00, 0xed, 0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f,
	0xa5, 0x45, 0x25, 0xc9, 0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4,
	0x3e, 0x0f, 0x23, 0xd8, 0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14, 0x1e, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x52, 0x12, 0x41,
	0xd8, 0xb3, 0xa7, 0x70, 0x99, 0x6b, 0xcf, 0xc9, 0xb9, 0xea, 0xd4, 0xe7,
	0xe0, 0xa1, 0xc0, 0xdb, 0x35, 0x3a, 0x3b, 0xdf, 0x29, 0x10, 0xb3, 0x92,
	0x75, 0xae, 0x48, 0xb7, 0x56, 0x01, 0x59, 0x81, 0x85, 0x0d, 0x27, 0xdb,
	0x67, 0x34, 0xe3, 0x7f, 0x67, 0x21, 0x22, 0x67, 0xdd, 0x05, 0xee, 0xff,
	0x27, 0xb9, 0xe7, 0xa8, 0x13, 0xfa, 0x57, 0x4b, 0x72, 0xa0, 0x0b, 0x43,
	0x0b,
};

/**
 * \brief Root X.509 public key. 
 */
static const uint8_t PK_CA[] = {
	0x2b, 0x7b, 0x3e, 0x80, 0x57, 0xc8, 0x64, 0x29, 0x44, 0xd0, 0x6a,
	0xfe, 0x7a, 0x71, 0xd1, 0xc9, 0xbf, 0x96, 0x1b, 0x62, 0x92, 0xba,
	0xc4, 0xb0, 0x4f, 0x91, 0x66, 0x9b, 0xbb, 0x71, 0x3b, 0xe4,
};

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* TEST_VECTOR_X5CHAIN_SIGN_KEYS_SUITE_0_H */
