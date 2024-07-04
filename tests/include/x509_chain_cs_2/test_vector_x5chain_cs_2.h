/**
 * \file    test_vector_x5chain_cs_2.h
 * \author  Kamil Kielbasa
 * \brief   Test vector with keys and certificates for P-256 curve.
 *          
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_VECTOR_X5CHAIN_CS_2_H
#define TEST_VECTOR_X5CHAIN_CS_2_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

/**
 * \brief EDHOC message 1.
 */

static const uint8_t METHOD = 0;

static const uint8_t SUITES_I[] = { 0x02 };

static const uint8_t X[] = {
	0x36, 0x8e, 0xc1, 0xf6, 0x9a, 0xeb, 0x65, 0x9b, 0xa3, 0x7d, 0x5a,
	0x8d, 0x45, 0xb2, 0x1b, 0xdc, 0x02, 0x99, 0xdc, 0xea, 0xa8, 0xef,
	0x23, 0x5f, 0x3c, 0xa4, 0x2c, 0xe3, 0x53, 0x0f, 0x95, 0x25,
};
static const uint8_t G_X[] = {
	0x8a, 0xf6, 0xf4, 0x30, 0xeb, 0xe1, 0x8d, 0x34, 0x18, 0x40, 0x17,
	0xa9, 0xa1, 0x1b, 0xf5, 0x11, 0xc8, 0xdf, 0xf8, 0xf8, 0x34, 0x73,
	0x0b, 0x96, 0xc1, 0xb7, 0xc8, 0xdb, 0xca, 0x2f, 0xc3, 0xb6,
};
static const uint8_t C_I[] = { -24 };

/**
 * \brief EDHOC message 2.
 */

static const uint8_t SUITES_R[] = { 0x02 };

static const uint8_t Y[] = {
	0xe2, 0xf4, 0x12, 0x67, 0x77, 0x20, 0x5e, 0x85, 0x3b, 0x43, 0x7d,
	0x6e, 0xac, 0xa1, 0xe1, 0xf7, 0x53, 0xcd, 0xcc, 0x3e, 0x2c, 0x69,
	0xfa, 0x88, 0x4b, 0x0a, 0x1a, 0x64, 0x09, 0x77, 0xe4, 0x18,
};

static const uint8_t G_Y[] = {
	0x41, 0x97, 0x01, 0xd7, 0xf0, 0x0a, 0x26, 0xc2, 0xdc, 0x58, 0x7a,
	0x36, 0xdd, 0x75, 0x25, 0x49, 0xf3, 0x37, 0x63, 0xc8, 0x93, 0x42,
	0x2c, 0x8e, 0xa0, 0xf9, 0x55, 0xa1, 0x3a, 0x4f, 0xf5, 0xd5,
};

static const uint8_t C_R[] = { -8 };

static const uint8_t SK_R[] = {
	0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31,
	0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03,
	0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac,
};

static const uint8_t PK_R[] = {
	0x04, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94,
	0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1,
	0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
	0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f,
	0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd,
	0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
};

static const uint8_t CRED_R[] = {
	0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
	0x02, 0x04, 0x61, 0xe9, 0x98, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
	0x31, 0x32, 0x30, 0x31, 0x37, 0x31, 0x33, 0x30, 0x32, 0x5a, 0x17, 0x0d,
	0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbb, 0xc3, 0x49, 0x60,
	0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48,
	0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20,
	0x46, 0xdd, 0x44, 0xf0, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c,
	0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6,
	0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x30, 0x19, 0x4e, 0xf5, 0xfc,
	0x65, 0xc8, 0xb7, 0x95, 0xcd, 0xcd, 0x0b, 0xb4, 0x31, 0xbf, 0x83, 0xee,
	0x67, 0x41, 0xc1, 0x37, 0x0c, 0x22, 0xc8, 0xeb, 0x8e, 0xe9, 0xed, 0xd2,
	0xa7, 0x05, 0x19, 0x02, 0x21, 0x00, 0xb5, 0x83, 0x0e, 0x9c, 0x89, 0xa6,
	0x2a, 0xc7, 0x3c, 0xe1, 0xeb, 0xce, 0x00, 0x61, 0x70, 0x7d, 0xb8, 0xa8,
	0x8e, 0x23, 0x70, 0x9b, 0x4a, 0xcc, 0x58, 0xa1, 0x31, 0x3b, 0x13, 0x3d,
	0x05, 0x58
};

/**
 * \brief EDHOC message 3.
 */

static const uint8_t SK_I[] = {
	0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17,
	0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43,
	0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
};

static const uint8_t PK_I[] = {
	0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6,
	0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf,
	0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
	0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33,
	0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6,
	0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

static const uint8_t CRED_I[] = {
	0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
	0x02, 0x04, 0x62, 0x32, 0xef, 0x6f, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
	0x33, 0x31, 0x37, 0x30, 0x38, 0x32, 0x31, 0x30, 0x33, 0x5a, 0x17, 0x0d,
	0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74,
	0x69, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xac, 0x75, 0xe9, 0xec,
	0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40,
	0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4,
	0x30, 0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a,
	0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2,
	0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x8c, 0x32, 0x3a, 0x1f,
	0x33, 0x21, 0x38, 0xaa, 0xb9, 0xd0, 0xbe, 0xaf, 0xb8, 0x5f, 0x8d, 0x5a,
	0x44, 0x07, 0x3c, 0x58, 0x0f, 0x59, 0x5b, 0xc5, 0x21, 0xef, 0x91, 0x3f,
	0x6e, 0xf4, 0x8d, 0x11, 0x02, 0x20, 0x6c, 0x0a, 0xf1, 0xa1, 0x85, 0xa4,
	0xe4, 0xde, 0x06, 0x35, 0x36, 0x99, 0x23, 0x1c, 0x73, 0x3a, 0x6e, 0x8d,
	0xd2, 0xdf, 0x65, 0x13, 0x96, 0x6c, 0x91, 0x30, 0x15, 0x2a, 0x07, 0xa2,
	0xbe, 0xde
};

/**
 * \brief Root X.509 public key. 
 */
static const uint8_t PK_CA[] = {
	0x04, 0x27, 0xec, 0xf4, 0xb4, 0x66, 0xd3, 0xcd, 0x61, 0x14, 0x4c,
	0x94, 0x40, 0x21, 0x83, 0x8d, 0x57, 0xbf, 0x67, 0x01, 0x97, 0x33,
	0x78, 0xa1, 0x5b, 0x3f, 0x5d, 0x27, 0x57, 0x5d, 0x34, 0xc4, 0xa9,
	0x7b, 0x79, 0xe0, 0xf2, 0x4b, 0x44, 0x6b, 0xca, 0x67, 0xe1, 0x3d,
	0x75, 0xd0, 0x95, 0x73, 0x12, 0x4b, 0x49, 0xb8, 0x38, 0xb1, 0x09,
	0x73, 0xf0, 0xfb, 0x67, 0xe1, 0x26, 0x05, 0x1c, 0x95, 0x95,
};

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* TEST_VECTOR_X5CHAIN_CS_2_H */
