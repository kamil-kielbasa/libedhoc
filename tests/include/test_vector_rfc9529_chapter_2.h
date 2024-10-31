/**
 * \file    test_vector_rfc9529_chapter_2.h
 * \author  Kamil Kielbasa
 * \brief   Test vector from EDHOC traces (RFC 9529) for chapter 2.
 *          It contains authentication with signatures, X.509 identified by 'x5t'.
 *          
 * \version 0.6
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_VECTOR_RFC9529_CHAPTER_2_H
#define TEST_VECTOR_RFC9529_CHAPTER_2_H

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

static const uint8_t X[] = {
	0x89, 0x2e, 0xc2, 0x8e, 0x5c, 0xb6, 0x66, 0x91, 0x08, 0x47, 0x05,
	0x39, 0x50, 0x0b, 0x70, 0x5e, 0x60, 0xd0, 0x08, 0xd3, 0x47, 0xc5,
	0x81, 0x7e, 0xe9, 0xf3, 0x32, 0x7c, 0x8a, 0x87, 0xbb, 0x03,
};

static const uint8_t G_X[] = {
	0x31, 0xf8, 0x2c, 0x7b, 0x5b, 0x9c, 0xbb, 0xf0, 0xf1, 0x94, 0xd9,
	0x13, 0xcc, 0x12, 0xef, 0x15, 0x32, 0xd3, 0x28, 0xef, 0x32, 0x63,
	0x2a, 0x48, 0x81, 0xa1, 0xc0, 0x70, 0x1e, 0x23, 0x7f, 0x04,
};

static const uint8_t C_I[] = { -14 };

static const uint8_t message_1[] = {
	0x00, 0x00, 0x58, 0x20, 0x31, 0xf8, 0x2c, 0x7b, 0x5b, 0x9c,
	0xbb, 0xf0, 0xf1, 0x94, 0xd9, 0x13, 0xcc, 0x12, 0xef, 0x15,
	0x32, 0xd3, 0x28, 0xef, 0x32, 0x63, 0x2a, 0x48, 0x81, 0xa1,
	0xc0, 0x70, 0x1e, 0x23, 0x7f, 0x04, 0x2d,
};

/**
 * \brief EDHOC message 2.
 */

static const uint8_t SUITES_R[] = { 0 };

static const uint8_t Y[] = {
	0xe6, 0x9c, 0x23, 0xfb, 0xf8, 0x1b, 0xc4, 0x35, 0x94, 0x24, 0x46,
	0x83, 0x7f, 0xe8, 0x27, 0xbf, 0x20, 0x6c, 0x8f, 0xa1, 0x0a, 0x39,
	0xdb, 0x47, 0x44, 0x9e, 0x5a, 0x81, 0x34, 0x21, 0xe1, 0xe8,
};

static const uint8_t G_Y[] = {
	0xdc, 0x88, 0xd2, 0xd5, 0x1d, 0xa5, 0xed, 0x67, 0xfc, 0x46, 0x16,
	0x35, 0x6b, 0xc8, 0xca, 0x74, 0xef, 0x9e, 0xbe, 0x8b, 0x38, 0x7e,
	0x62, 0x3a, 0x36, 0x0b, 0xa4, 0x80, 0xb9, 0xb2, 0x9d, 0x1c,
};

static const uint8_t C_R[] = { 24 };

static const uint8_t H_message_1[] = {
	0xc1, 0x65, 0xd6, 0xa9, 0x9d, 0x1b, 0xca, 0xfa, 0xac, 0x8d, 0xbf,
	0x2b, 0x35, 0x2a, 0x6f, 0x7d, 0x71, 0xa3, 0x0b, 0x43, 0x9c, 0x9d,
	0x64, 0xd3, 0x49, 0xa2, 0x38, 0x48, 0x03, 0x8e, 0xd1, 0x6b,
};

static const uint8_t TH_2[] = {
	0xc6, 0x40, 0x5c, 0x15, 0x4c, 0x56, 0x74, 0x66, 0xab, 0x1d, 0xf2,
	0x03, 0x69, 0x50, 0x0e, 0x54, 0x0e, 0x9f, 0x14, 0xbd, 0x3a, 0x79,
	0x6a, 0x06, 0x52, 0xca, 0xe6, 0x6c, 0x90, 0x61, 0x68, 0x8d,
};

static const uint8_t G_XY[] = {
	0xe5, 0xcd, 0xf3, 0xa9, 0x86, 0xcd, 0xac, 0x5b, 0x7b, 0xf0, 0x46,
	0x91, 0xe2, 0xb0, 0x7c, 0x08, 0xe7, 0x1f, 0x53, 0x99, 0x8d, 0x8f,
	0x84, 0x2b, 0x7c, 0x3f, 0xb4, 0xd8, 0x39, 0xcf, 0x7b, 0x28,
};

static const uint8_t PRK_2e[] = {
	0xd5, 0x84, 0xac, 0x2e, 0x5d, 0xad, 0x5a, 0x77, 0xd1, 0x4b, 0x53,
	0xeb, 0xe7, 0x2e, 0xf1, 0xd5, 0xda, 0xa8, 0x86, 0x0d, 0x39, 0x93,
	0x73, 0xbf, 0x2c, 0x24, 0x0a, 0xfa, 0x7b, 0xa8, 0x04, 0xda,
};

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

static const uint8_t PRK_3e2m[] = {
	0xd5, 0x84, 0xac, 0x2e, 0x5d, 0xad, 0x5a, 0x77, 0xd1, 0x4b, 0x53,
	0xeb, 0xe7, 0x2e, 0xf1, 0xd5, 0xda, 0xa8, 0x86, 0x0d, 0x39, 0x93,
	0x73, 0xbf, 0x2c, 0x24, 0x0a, 0xfa, 0x7b, 0xa8, 0x04, 0xda,
};

static const uint8_t ID_CRED_R_cborised[] = {
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x79,
	0xf2, 0xa4, 0x1b, 0x51, 0x0c, 0x1f, 0x9b,
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

static const uint8_t CRED_R_cborised[] = {
	0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xc4, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f,
	0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17,
	0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x33,
	0x36, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
	0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x45, 0x64,
	0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x03, 0x21, 0x00, 0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85,
	0x4a, 0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a,
	0xa0, 0xf2, 0xc6, 0x62, 0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93,
	0x59, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xb7,
	0x23, 0xbc, 0x01, 0xea, 0xb0, 0x92, 0x8e, 0x8b, 0x2b, 0x6c, 0x98, 0xde,
	0x19, 0xcc, 0x38, 0x23, 0xd4, 0x6e, 0x7d, 0x69, 0x87, 0xb0, 0x32, 0x47,
	0x8f, 0xec, 0xfa, 0xf1, 0x45, 0x37, 0xa1, 0xaf, 0x14, 0xcc, 0x8b, 0xe8,
	0x29, 0xc6, 0xb7, 0x30, 0x44, 0x10, 0x18, 0x37, 0xeb, 0x4a, 0xbc, 0x94,
	0x95, 0x65, 0xd8, 0x6d, 0xce, 0x51, 0xcf, 0xae, 0x52, 0xab, 0x82, 0xc1,
	0x52, 0xcb, 0x02,
};

static const uint8_t context_2[] = {
	0x41, 0x18, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x79, 0xf2, 0xa4, 0x1b,
	0x51, 0x0c, 0x1f, 0x9b, 0x58, 0x20, 0xc6, 0x40, 0x5c, 0x15, 0x4c, 0x56,
	0x74, 0x66, 0xab, 0x1d, 0xf2, 0x03, 0x69, 0x50, 0x0e, 0x54, 0x0e, 0x9f,
	0x14, 0xbd, 0x3a, 0x79, 0x6a, 0x06, 0x52, 0xca, 0xe6, 0x6c, 0x90, 0x61,
	0x68, 0x8d, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03,
	0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xc4, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52,
	0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30,
	0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32,
	0x34, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31,
	0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30,
	0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f,
	0x43, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x20,
	0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xa1, 0xdb, 0x47, 0xb9, 0x51,
	0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac,
	0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9,
	0x2f, 0x93, 0x59, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41,
	0x00, 0xb7, 0x23, 0xbc, 0x01, 0xea, 0xb0, 0x92, 0x8e, 0x8b, 0x2b, 0x6c,
	0x98, 0xde, 0x19, 0xcc, 0x38, 0x23, 0xd4, 0x6e, 0x7d, 0x69, 0x87, 0xb0,
	0x32, 0x47, 0x8f, 0xec, 0xfa, 0xf1, 0x45, 0x37, 0xa1, 0xaf, 0x14, 0xcc,
	0x8b, 0xe8, 0x29, 0xc6, 0xb7, 0x30, 0x44, 0x10, 0x18, 0x37, 0xeb, 0x4a,
	0xbc, 0x94, 0x95, 0x65, 0xd8, 0x6d, 0xce, 0x51, 0xcf, 0xae, 0x52, 0xab,
	0x82, 0xc1, 0x52, 0xcb, 0x02,
};

static const uint8_t MAC_2_info_cborised[] = {
	0x02, 0x59, 0x01, 0x25, 0x41, 0x18, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48,
	0x79, 0xf2, 0xa4, 0x1b, 0x51, 0x0c, 0x1f, 0x9b, 0x58, 0x20, 0xc6, 0x40,
	0x5c, 0x15, 0x4c, 0x56, 0x74, 0x66, 0xab, 0x1d, 0xf2, 0x03, 0x69, 0x50,
	0x0e, 0x54, 0x0e, 0x9f, 0x14, 0xbd, 0x3a, 0x79, 0x6a, 0x06, 0x52, 0xca,
	0xe6, 0x6c, 0x90, 0x61, 0x68, 0x8d, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30,
	0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e,
	0xc4, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b,
	0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48,
	0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31,
	0x36, 0x30, 0x38, 0x32, 0x34, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x39,
	0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30,
	0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17,
	0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x64, 0x65, 0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30,
	0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xa1,
	0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c, 0x1a, 0x35,
	0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0, 0x0b,
	0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x03, 0x41, 0x00, 0xb7, 0x23, 0xbc, 0x01, 0xea, 0xb0, 0x92,
	0x8e, 0x8b, 0x2b, 0x6c, 0x98, 0xde, 0x19, 0xcc, 0x38, 0x23, 0xd4, 0x6e,
	0x7d, 0x69, 0x87, 0xb0, 0x32, 0x47, 0x8f, 0xec, 0xfa, 0xf1, 0x45, 0x37,
	0xa1, 0xaf, 0x14, 0xcc, 0x8b, 0xe8, 0x29, 0xc6, 0xb7, 0x30, 0x44, 0x10,
	0x18, 0x37, 0xeb, 0x4a, 0xbc, 0x94, 0x95, 0x65, 0xd8, 0x6d, 0xce, 0x51,
	0xcf, 0xae, 0x52, 0xab, 0x82, 0xc1, 0x52, 0xcb, 0x02, 0x18, 0x20,
};

static const uint8_t MAC_2[] = {
	0x86, 0x2a, 0x7e, 0x5e, 0xf1, 0x47, 0xf9, 0xa5, 0xf4, 0xc5, 0x12,
	0xe1, 0xb6, 0x62, 0x3c, 0xd6, 0x6c, 0xd1, 0x7a, 0x72, 0x72, 0x07,
	0x2b, 0xfe, 0x5b, 0x60, 0x2f, 0xfe, 0x30, 0x7e, 0xe0, 0xe9,
};

static const uint8_t Signature_or_MAC_2_input[] = {
	0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
	0x4e, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x79, 0xf2, 0xa4, 0x1b, 0x51,
	0x0c, 0x1f, 0x9b, 0x59, 0x01, 0x15, 0x58, 0x20, 0xc6, 0x40, 0x5c, 0x15,
	0x4c, 0x56, 0x74, 0x66, 0xab, 0x1d, 0xf2, 0x03, 0x69, 0x50, 0x0e, 0x54,
	0x0e, 0x9f, 0x14, 0xbd, 0x3a, 0x79, 0x6a, 0x06, 0x52, 0xca, 0xe6, 0x6c,
	0x90, 0x61, 0x68, 0x8d, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1,
	0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xc4, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
	0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30,
	0x38, 0x32, 0x34, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32,
	0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31,
	0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44,
	0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65,
	0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xa1, 0xdb, 0x47,
	0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41,
	0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0, 0x0b, 0x3a, 0xc5,
	0x5d, 0xe9, 0x2f, 0x93, 0x59, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x41, 0x00, 0xb7, 0x23, 0xbc, 0x01, 0xea, 0xb0, 0x92, 0x8e, 0x8b,
	0x2b, 0x6c, 0x98, 0xde, 0x19, 0xcc, 0x38, 0x23, 0xd4, 0x6e, 0x7d, 0x69,
	0x87, 0xb0, 0x32, 0x47, 0x8f, 0xec, 0xfa, 0xf1, 0x45, 0x37, 0xa1, 0xaf,
	0x14, 0xcc, 0x8b, 0xe8, 0x29, 0xc6, 0xb7, 0x30, 0x44, 0x10, 0x18, 0x37,
	0xeb, 0x4a, 0xbc, 0x94, 0x95, 0x65, 0xd8, 0x6d, 0xce, 0x51, 0xcf, 0xae,
	0x52, 0xab, 0x82, 0xc1, 0x52, 0xcb, 0x02, 0x58, 0x20, 0x86, 0x2a, 0x7e,
	0x5e, 0xf1, 0x47, 0xf9, 0xa5, 0xf4, 0xc5, 0x12, 0xe1, 0xb6, 0x62, 0x3c,
	0xd6, 0x6c, 0xd1, 0x7a, 0x72, 0x72, 0x07, 0x2b, 0xfe, 0x5b, 0x60, 0x2f,
	0xfe, 0x30, 0x7e, 0xe0, 0xe9,
};

static const uint8_t Signature_or_MAC_2[] = {
	0xc3, 0xb5, 0xbd, 0x44, 0xd1, 0xe4, 0x4a, 0x08, 0x5c, 0x03, 0xd3,
	0xae, 0xde, 0x4e, 0x1e, 0x6c, 0x11, 0xc5, 0x72, 0xa1, 0x96, 0x8c,
	0xc3, 0x62, 0x9b, 0x50, 0x5f, 0x98, 0xc6, 0x81, 0x60, 0x8d, 0x3d,
	0x1d, 0xe7, 0x93, 0xd1, 0xc4, 0x0e, 0xb5, 0xdd, 0x5d, 0x89, 0xac,
	0xf1, 0x96, 0x6a, 0xea, 0x07, 0x02, 0x2b, 0x48, 0xcd, 0xc9, 0x98,
	0x70, 0xeb, 0xc4, 0x03, 0x74, 0xe8, 0xfa, 0x6e, 0x09,
};

static const uint8_t PLAINTEXT_2[] = {
	0x41, 0x18, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x79, 0xf2, 0xa4, 0x1b,
	0x51, 0x0c, 0x1f, 0x9b, 0x58, 0x40, 0xc3, 0xb5, 0xbd, 0x44, 0xd1, 0xe4,
	0x4a, 0x08, 0x5c, 0x03, 0xd3, 0xae, 0xde, 0x4e, 0x1e, 0x6c, 0x11, 0xc5,
	0x72, 0xa1, 0x96, 0x8c, 0xc3, 0x62, 0x9b, 0x50, 0x5f, 0x98, 0xc6, 0x81,
	0x60, 0x8d, 0x3d, 0x1d, 0xe7, 0x93, 0xd1, 0xc4, 0x0e, 0xb5, 0xdd, 0x5d,
	0x89, 0xac, 0xf1, 0x96, 0x6a, 0xea, 0x07, 0x02, 0x2b, 0x48, 0xcd, 0xc9,
	0x98, 0x70, 0xeb, 0xc4, 0x03, 0x74, 0xe8, 0xfa, 0x6e, 0x09,
};

static const uint8_t KEYSTREAM_2_info[] = {
	0x00, 0x58, 0x20, 0xc6, 0x40, 0x5c, 0x15, 0x4c, 0x56, 0x74,
	0x66, 0xab, 0x1d, 0xf2, 0x03, 0x69, 0x50, 0x0e, 0x54, 0x0e,
	0x9f, 0x14, 0xbd, 0x3a, 0x79, 0x6a, 0x06, 0x52, 0xca, 0xe6,
	0x6c, 0x90, 0x61, 0x68, 0x8d, 0x18, 0x52,
};

static const uint8_t KEYSTERAM_2[] = {
	0xfd, 0x3e, 0x7c, 0x3f, 0x2d, 0x6b, 0xee, 0x64, 0x3d, 0x3c, 0x9d, 0x2f,
	0x28, 0x47, 0x03, 0x5d, 0x73, 0xe2, 0xec, 0xb0, 0xf8, 0xdb, 0x5c, 0xd1,
	0xc6, 0x85, 0x4e, 0x24, 0x89, 0x6a, 0xf2, 0x11, 0x88, 0xb2, 0xc4, 0x34,
	0x4e, 0x68, 0x9e, 0xc2, 0x98, 0x42, 0x83, 0xd9, 0xfb, 0xc6, 0x9c, 0xe1,
	0xc5, 0xdb, 0x10, 0xdc, 0xff, 0xf2, 0x4d, 0xf9, 0xa4, 0x9a, 0x04, 0xa9,
	0x40, 0x58, 0x27, 0x7b, 0xc7, 0xfa, 0x9a, 0xd6, 0xc6, 0xb1, 0x94, 0xab,
	0x32, 0x8b, 0x44, 0x5e, 0xb0, 0x80, 0x49, 0x0c, 0xd7, 0x86,
};

static const uint8_t CIPHERTEXT_2[] = {
	0xbc, 0x26, 0xdd, 0x27, 0x0f, 0xe9, 0xc0, 0x2c, 0x44, 0xce, 0x39, 0x34,
	0x79, 0x4b, 0x1c, 0xc6, 0x2b, 0xa2, 0x2f, 0x05, 0x45, 0x9f, 0x8d, 0x35,
	0x8c, 0x8d, 0x12, 0x27, 0x5a, 0xc4, 0x2c, 0x5f, 0x96, 0xde, 0xd5, 0xf1,
	0x3c, 0xc9, 0x08, 0x4e, 0x5b, 0x20, 0x18, 0x89, 0xa4, 0x5e, 0x5a, 0x60,
	0xa5, 0x56, 0x2d, 0xc1, 0x18, 0x61, 0x9c, 0x3d, 0xaa, 0x2f, 0xd9, 0xf4,
	0xc9, 0xf4, 0xd6, 0xed, 0xad, 0x10, 0x9d, 0xd4, 0xed, 0xf9, 0x59, 0x62,
	0xaa, 0xfb, 0xaf, 0x9a, 0xb3, 0xf4, 0xa1, 0xf6, 0xb9, 0x8f,
};

static const uint8_t message_2[] = {
	0x58, 0x72, 0xdc, 0x88, 0xd2, 0xd5, 0x1d, 0xa5, 0xed, 0x67, 0xfc, 0x46,
	0x16, 0x35, 0x6b, 0xc8, 0xca, 0x74, 0xef, 0x9e, 0xbe, 0x8b, 0x38, 0x7e,
	0x62, 0x3a, 0x36, 0x0b, 0xa4, 0x80, 0xb9, 0xb2, 0x9d, 0x1c, 0xbc, 0x26,
	0xdd, 0x27, 0x0f, 0xe9, 0xc0, 0x2c, 0x44, 0xce, 0x39, 0x34, 0x79, 0x4b,
	0x1c, 0xc6, 0x2b, 0xa2, 0x2f, 0x05, 0x45, 0x9f, 0x8d, 0x35, 0x8c, 0x8d,
	0x12, 0x27, 0x5a, 0xc4, 0x2c, 0x5f, 0x96, 0xde, 0xd5, 0xf1, 0x3c, 0xc9,
	0x08, 0x4e, 0x5b, 0x20, 0x18, 0x89, 0xa4, 0x5e, 0x5a, 0x60, 0xa5, 0x56,
	0x2d, 0xc1, 0x18, 0x61, 0x9c, 0x3d, 0xaa, 0x2f, 0xd9, 0xf4, 0xc9, 0xf4,
	0xd6, 0xed, 0xad, 0x10, 0x9d, 0xd4, 0xed, 0xf9, 0x59, 0x62, 0xaa, 0xfb,
	0xaf, 0x9a, 0xb3, 0xf4, 0xa1, 0xf6, 0xb9, 0x8f,
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

static const uint8_t TH_3_input[] = {
	0x58, 0x20, 0xc6, 0x40, 0x5c, 0x15, 0x4c, 0x56, 0x74, 0x66, 0xab, 0x1d,
	0xf2, 0x03, 0x69, 0x50, 0x0e, 0x54, 0x0e, 0x9f, 0x14, 0xbd, 0x3a, 0x79,
	0x6a, 0x06, 0x52, 0xca, 0xe6, 0x6c, 0x90, 0x61, 0x68, 0x8d, 0x41, 0x18,
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x79, 0xf2, 0xa4, 0x1b, 0x51, 0x0c,
	0x1f, 0x9b, 0x58, 0x40, 0xc3, 0xb5, 0xbd, 0x44, 0xd1, 0xe4, 0x4a, 0x08,
	0x5c, 0x03, 0xd3, 0xae, 0xde, 0x4e, 0x1e, 0x6c, 0x11, 0xc5, 0x72, 0xa1,
	0x96, 0x8c, 0xc3, 0x62, 0x9b, 0x50, 0x5f, 0x98, 0xc6, 0x81, 0x60, 0x8d,
	0x3d, 0x1d, 0xe7, 0x93, 0xd1, 0xc4, 0x0e, 0xb5, 0xdd, 0x5d, 0x89, 0xac,
	0xf1, 0x96, 0x6a, 0xea, 0x07, 0x02, 0x2b, 0x48, 0xcd, 0xc9, 0x98, 0x70,
	0xeb, 0xc4, 0x03, 0x74, 0xe8, 0xfa, 0x6e, 0x09, 0x58, 0xf1, 0x30, 0x81,
	0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62,
	0x31, 0x9e, 0xc4, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d,
	0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45,
	0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64,
	0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
	0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x33, 0x36, 0x5a, 0x17, 0x0d,
	0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
	0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
	0x00, 0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a, 0xd1, 0x2a, 0x0c,
	0x1a, 0x35, 0x4e, 0x41, 0x8a, 0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62,
	0xc0, 0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xb7, 0x23, 0xbc, 0x01, 0xea,
	0xb0, 0x92, 0x8e, 0x8b, 0x2b, 0x6c, 0x98, 0xde, 0x19, 0xcc, 0x38, 0x23,
	0xd4, 0x6e, 0x7d, 0x69, 0x87, 0xb0, 0x32, 0x47, 0x8f, 0xec, 0xfa, 0xf1,
	0x45, 0x37, 0xa1, 0xaf, 0x14, 0xcc, 0x8b, 0xe8, 0x29, 0xc6, 0xb7, 0x30,
	0x44, 0x10, 0x18, 0x37, 0xeb, 0x4a, 0xbc, 0x94, 0x95, 0x65, 0xd8, 0x6d,
	0xce, 0x51, 0xcf, 0xae, 0x52, 0xab, 0x82, 0xc1, 0x52, 0xcb, 0x02,
};

static const uint8_t TH_3[] = {
	0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c, 0xe0, 0x41, 0x8e,
	0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca, 0x57, 0xf6,
	0x69, 0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc,
};

static const uint8_t PRK_4e3m[] = {
	0xd5, 0x84, 0xac, 0x2e, 0x5d, 0xad, 0x5a, 0x77, 0xd1, 0x4b, 0x53,
	0xeb, 0xe7, 0x2e, 0xf1, 0xd5, 0xda, 0xa8, 0x86, 0x0d, 0x39, 0x93,
	0x73, 0xbf, 0x2c, 0x24, 0x0a, 0xfa, 0x7b, 0xa8, 0x04, 0xda,
};

static const uint8_t ID_CRED_I_cborised[] = {
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xc2,
	0x4a, 0xb2, 0xfd, 0x76, 0x43, 0xc7, 0x9f,
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

static const uint8_t CRED_I_cborised[] = {
	0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xa0, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f,
	0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17,
	0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x30,
	0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
	0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20,
	0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x45, 0x64,
	0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x03, 0x21, 0x00, 0xed, 0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29,
	0xba, 0x5f, 0xa5, 0x45, 0x25, 0xc9, 0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3,
	0x02, 0xf4, 0x3e, 0x0f, 0x23, 0xd8, 0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14,
	0x1e, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x52,
	0x12, 0x41, 0xd8, 0xb3, 0xa7, 0x70, 0x99, 0x6b, 0xcf, 0xc9, 0xb9, 0xea,
	0xd4, 0xe7, 0xe0, 0xa1, 0xc0, 0xdb, 0x35, 0x3a, 0x3b, 0xdf, 0x29, 0x10,
	0xb3, 0x92, 0x75, 0xae, 0x48, 0xb7, 0x56, 0x01, 0x59, 0x81, 0x85, 0x0d,
	0x27, 0xdb, 0x67, 0x34, 0xe3, 0x7f, 0x67, 0x21, 0x22, 0x67, 0xdd, 0x05,
	0xee, 0xff, 0x27, 0xb9, 0xe7, 0xa8, 0x13, 0xfa, 0x57, 0x4b, 0x72, 0xa0,
	0x0b, 0x43, 0x0b,
};

static const uint8_t context_3[] = {
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xc2, 0x4a, 0xb2, 0xfd, 0x76, 0x43,
	0xc7, 0x9f, 0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c,
	0xe0, 0x41, 0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca,
	0x57, 0xf6, 0x69, 0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc,
	0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xa0, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f,
	0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1e, 0x17,
	0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30, 0x38, 0x32, 0x34, 0x30,
	0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
	0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20,
	0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x45, 0x64,
	0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x03, 0x21, 0x00, 0xed, 0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29,
	0xba, 0x5f, 0xa5, 0x45, 0x25, 0xc9, 0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3,
	0x02, 0xf4, 0x3e, 0x0f, 0x23, 0xd8, 0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14,
	0x1e, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x52,
	0x12, 0x41, 0xd8, 0xb3, 0xa7, 0x70, 0x99, 0x6b, 0xcf, 0xc9, 0xb9, 0xea,
	0xd4, 0xe7, 0xe0, 0xa1, 0xc0, 0xdb, 0x35, 0x3a, 0x3b, 0xdf, 0x29, 0x10,
	0xb3, 0x92, 0x75, 0xae, 0x48, 0xb7, 0x56, 0x01, 0x59, 0x81, 0x85, 0x0d,
	0x27, 0xdb, 0x67, 0x34, 0xe3, 0x7f, 0x67, 0x21, 0x22, 0x67, 0xdd, 0x05,
	0xee, 0xff, 0x27, 0xb9, 0xe7, 0xa8, 0x13, 0xfa, 0x57, 0x4b, 0x72, 0xa0,
	0x0b, 0x43, 0x0b,
};

static const uint8_t MAC_3_info[] = {
	0x06, 0x59, 0x01, 0x23, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xc2, 0x4a,
	0xb2, 0xfd, 0x76, 0x43, 0xc7, 0x9f, 0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4,
	0xf5, 0x8f, 0x24, 0x0c, 0xe0, 0x41, 0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff,
	0x3a, 0x22, 0xb5, 0xca, 0x57, 0xf6, 0x69, 0xb1, 0x67, 0x77, 0x99, 0x65,
	0x92, 0xe9, 0x28, 0xbc, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1,
	0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xa0, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
	0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30,
	0x38, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32,
	0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31,
	0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44,
	0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f,
	0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xed, 0x06, 0xa8,
	0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f, 0xa5, 0x45, 0x25, 0xc9, 0xd0, 0x7f,
	0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4, 0x3e, 0x0f, 0x23, 0xd8, 0xcc, 0x20,
	0xb7, 0x30, 0x85, 0x14, 0x1e, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x41, 0x00, 0x52, 0x12, 0x41, 0xd8, 0xb3, 0xa7, 0x70, 0x99, 0x6b,
	0xcf, 0xc9, 0xb9, 0xea, 0xd4, 0xe7, 0xe0, 0xa1, 0xc0, 0xdb, 0x35, 0x3a,
	0x3b, 0xdf, 0x29, 0x10, 0xb3, 0x92, 0x75, 0xae, 0x48, 0xb7, 0x56, 0x01,
	0x59, 0x81, 0x85, 0x0d, 0x27, 0xdb, 0x67, 0x34, 0xe3, 0x7f, 0x67, 0x21,
	0x22, 0x67, 0xdd, 0x05, 0xee, 0xff, 0x27, 0xb9, 0xe7, 0xa8, 0x13, 0xfa,
	0x57, 0x4b, 0x72, 0xa0, 0x0b, 0x43, 0x0b, 0x18, 0x20,
};

static const uint8_t MAC_3[] = {
	0x39, 0xb1, 0x27, 0xc1, 0x30, 0x12, 0x9a, 0xfa, 0x30, 0x61, 0x8c,
	0x75, 0x13, 0x29, 0xe6, 0x37, 0xcc, 0x37, 0x34, 0x27, 0x0d, 0x4b,
	0x01, 0x25, 0x84, 0x45, 0xa8, 0xee, 0x02, 0xda, 0xa3, 0xbd,
};

static const uint8_t Signature_or_MAC_3_input[] = {
	0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
	0x4e, 0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xc2, 0x4a, 0xb2, 0xfd, 0x76,
	0x43, 0xc7, 0x9f, 0x59, 0x01, 0x15, 0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4,
	0xf5, 0x8f, 0x24, 0x0c, 0xe0, 0x41, 0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff,
	0x3a, 0x22, 0xb5, 0xca, 0x57, 0xf6, 0x69, 0xb1, 0x67, 0x77, 0x99, 0x65,
	0x92, 0xe9, 0x28, 0xbc, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30, 0x81, 0xa1,
	0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e, 0xa0, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b, 0x30, 0x19,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
	0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x36, 0x30,
	0x38, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x31, 0x32,
	0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31,
	0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x45, 0x44,
	0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f,
	0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2a, 0x30,
	0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xed, 0x06, 0xa8,
	0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f, 0xa5, 0x45, 0x25, 0xc9, 0xd0, 0x7f,
	0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4, 0x3e, 0x0f, 0x23, 0xd8, 0xcc, 0x20,
	0xb7, 0x30, 0x85, 0x14, 0x1e, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x41, 0x00, 0x52, 0x12, 0x41, 0xd8, 0xb3, 0xa7, 0x70, 0x99, 0x6b,
	0xcf, 0xc9, 0xb9, 0xea, 0xd4, 0xe7, 0xe0, 0xa1, 0xc0, 0xdb, 0x35, 0x3a,
	0x3b, 0xdf, 0x29, 0x10, 0xb3, 0x92, 0x75, 0xae, 0x48, 0xb7, 0x56, 0x01,
	0x59, 0x81, 0x85, 0x0d, 0x27, 0xdb, 0x67, 0x34, 0xe3, 0x7f, 0x67, 0x21,
	0x22, 0x67, 0xdd, 0x05, 0xee, 0xff, 0x27, 0xb9, 0xe7, 0xa8, 0x13, 0xfa,
	0x57, 0x4b, 0x72, 0xa0, 0x0b, 0x43, 0x0b, 0x58, 0x20, 0x39, 0xb1, 0x27,
	0xc1, 0x30, 0x12, 0x9a, 0xfa, 0x30, 0x61, 0x8c, 0x75, 0x13, 0x29, 0xe6,
	0x37, 0xcc, 0x37, 0x34, 0x27, 0x0d, 0x4b, 0x01, 0x25, 0x84, 0x45, 0xa8,
	0xee, 0x02, 0xda, 0xa3, 0xbd,
};

static const uint8_t Signature_or_MAC_3[] = {
	0x96, 0xe1, 0xcd, 0x5f, 0xce, 0xad, 0xfa, 0xc1, 0xb5, 0xaf, 0x81,
	0x94, 0x43, 0xf7, 0x09, 0x24, 0xf5, 0x71, 0x99, 0x55, 0x95, 0x7f,
	0xd0, 0x26, 0x55, 0xbe, 0xb4, 0x77, 0x5e, 0x1a, 0x73, 0x18, 0x6a,
	0x0d, 0x1d, 0x3e, 0xa6, 0x83, 0xf0, 0x8f, 0x8d, 0x03, 0xdc, 0xec,
	0xb9, 0xcf, 0x15, 0x4e, 0x1c, 0x6f, 0x55, 0x5a, 0x1e, 0x12, 0xca,
	0x11, 0x8c, 0xe4, 0x2b, 0xdb, 0xa6, 0x87, 0x89, 0x07,
};

static const uint8_t PLAINTET_3[] = {
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xc2, 0x4a, 0xb2, 0xfd, 0x76, 0x43,
	0xc7, 0x9f, 0x58, 0x40, 0x96, 0xe1, 0xcd, 0x5f, 0xce, 0xad, 0xfa, 0xc1,
	0xb5, 0xaf, 0x81, 0x94, 0x43, 0xf7, 0x09, 0x24, 0xf5, 0x71, 0x99, 0x55,
	0x95, 0x7f, 0xd0, 0x26, 0x55, 0xbe, 0xb4, 0x77, 0x5e, 0x1a, 0x73, 0x18,
	0x6a, 0x0d, 0x1d, 0x3e, 0xa6, 0x83, 0xf0, 0x8f, 0x8d, 0x03, 0xdc, 0xec,
	0xb9, 0xcf, 0x15, 0x4e, 0x1c, 0x6f, 0x55, 0x5a, 0x1e, 0x12, 0xca, 0x11,
	0x8c, 0xe4, 0x2b, 0xdb, 0xa6, 0x87, 0x89, 0x07,
};

static const uint8_t A_3[] = {
	0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40, 0x58,
	0x20, 0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c, 0xe0, 0x41, 0x8e,
	0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca, 0x57, 0xf6, 0x69,
	0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc,
};

static const uint8_t K_3_info[] = {
	0x03, 0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c, 0xe0,
	0x41, 0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca, 0x57,
	0xf6, 0x69, 0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc, 0x10,
};

static const uint8_t K_3[] = {
	0xda, 0x19, 0x5e, 0x5f, 0x64, 0x8a, 0xc6, 0x3b,
	0x0e, 0x8f, 0xb0, 0xc4, 0x55, 0x20, 0x51, 0x39,
};

static const uint8_t IV_3_info[] = {
	0x04, 0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c, 0xe0,
	0x41, 0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca, 0x57,
	0xf6, 0x69, 0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc, 0x0d,
};

static const uint8_t IV_3[] = {
	0x38, 0xd8, 0xc6, 0x4c, 0x56, 0x25, 0x5a,
	0xff, 0xa4, 0x49, 0xf4, 0xbe, 0xd7,
};

static const uint8_t CIPHERTEXT_3[] = {
	0x25, 0xc3, 0x45, 0x88, 0x4a, 0xaa, 0xeb, 0x22, 0xc5, 0x27, 0xf9,
	0xb1, 0xd2, 0xb6, 0x78, 0x72, 0x07, 0xe0, 0x16, 0x3c, 0x69, 0xb6,
	0x2a, 0x0d, 0x43, 0x92, 0x81, 0x50, 0x42, 0x72, 0x03, 0xc3, 0x16,
	0x74, 0xe4, 0x51, 0x4e, 0xa6, 0xe3, 0x83, 0xb5, 0x66, 0xeb, 0x29,
	0x76, 0x3e, 0xfe, 0xb0, 0xaf, 0xa5, 0x18, 0x77, 0x6a, 0xe1, 0xc6,
	0x5f, 0x85, 0x6d, 0x84, 0xbf, 0x32, 0xaf, 0x3a, 0x78, 0x36, 0x97,
	0x04, 0x66, 0xdc, 0xb7, 0x1f, 0x76, 0x74, 0x5d, 0x39, 0xd3, 0x02,
	0x5e, 0x77, 0x03, 0xe0, 0xc0, 0x32, 0xeb, 0xad, 0x51, 0x94, 0x7c,
};

static const uint8_t message_3[] = {
	0x58, 0x58, 0x25, 0xc3, 0x45, 0x88, 0x4a, 0xaa, 0xeb, 0x22, 0xc5, 0x27,
	0xf9, 0xb1, 0xd2, 0xb6, 0x78, 0x72, 0x07, 0xe0, 0x16, 0x3c, 0x69, 0xb6,
	0x2a, 0x0d, 0x43, 0x92, 0x81, 0x50, 0x42, 0x72, 0x03, 0xc3, 0x16, 0x74,
	0xe4, 0x51, 0x4e, 0xa6, 0xe3, 0x83, 0xb5, 0x66, 0xeb, 0x29, 0x76, 0x3e,
	0xfe, 0xb0, 0xaf, 0xa5, 0x18, 0x77, 0x6a, 0xe1, 0xc6, 0x5f, 0x85, 0x6d,
	0x84, 0xbf, 0x32, 0xaf, 0x3a, 0x78, 0x36, 0x97, 0x04, 0x66, 0xdc, 0xb7,
	0x1f, 0x76, 0x74, 0x5d, 0x39, 0xd3, 0x02, 0x5e, 0x77, 0x03, 0xe0, 0xc0,
	0x32, 0xeb, 0xad, 0x51, 0x94, 0x7c,
};

static const uint8_t TH_4_input[] = {
	0x58, 0x20, 0x5b, 0x7d, 0xf9, 0xb4, 0xf5, 0x8f, 0x24, 0x0c, 0xe0, 0x41,
	0x8e, 0x48, 0x19, 0x1b, 0x5f, 0xff, 0x3a, 0x22, 0xb5, 0xca, 0x57, 0xf6,
	0x69, 0xb1, 0x67, 0x77, 0x99, 0x65, 0x92, 0xe9, 0x28, 0xbc, 0xa1, 0x18,
	0x22, 0x82, 0x2e, 0x48, 0xc2, 0x4a, 0xb2, 0xfd, 0x76, 0x43, 0xc7, 0x9f,
	0x58, 0x40, 0x96, 0xe1, 0xcd, 0x5f, 0xce, 0xad, 0xfa, 0xc1, 0xb5, 0xaf,
	0x81, 0x94, 0x43, 0xf7, 0x09, 0x24, 0xf5, 0x71, 0x99, 0x55, 0x95, 0x7f,
	0xd0, 0x26, 0x55, 0xbe, 0xb4, 0x77, 0x5e, 0x1a, 0x73, 0x18, 0x6a, 0x0d,
	0x1d, 0x3e, 0xa6, 0x83, 0xf0, 0x8f, 0x8d, 0x03, 0xdc, 0xec, 0xb9, 0xcf,
	0x15, 0x4e, 0x1c, 0x6f, 0x55, 0x5a, 0x1e, 0x12, 0xca, 0x11, 0x8c, 0xe4,
	0x2b, 0xdb, 0xa6, 0x87, 0x89, 0x07, 0x58, 0xf1, 0x30, 0x81, 0xee, 0x30,
	0x81, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x31, 0x9e,
	0xa0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1d, 0x31, 0x1b,
	0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x45, 0x44, 0x48,
	0x4f, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x33, 0x31,
	0x36, 0x30, 0x38, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39,
	0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30,
	0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17,
	0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61,
	0x74, 0x6f, 0x72, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30,
	0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xed,
	0x06, 0xa8, 0xae, 0x61, 0xa8, 0x29, 0xba, 0x5f, 0xa5, 0x45, 0x25, 0xc9,
	0xd0, 0x7f, 0x48, 0xdd, 0x44, 0xa3, 0x02, 0xf4, 0x3e, 0x0f, 0x23, 0xd8,
	0xcc, 0x20, 0xb7, 0x30, 0x85, 0x14, 0x1e, 0x30, 0x05, 0x06, 0x03, 0x2b,
	0x65, 0x70, 0x03, 0x41, 0x00, 0x52, 0x12, 0x41, 0xd8, 0xb3, 0xa7, 0x70,
	0x99, 0x6b, 0xcf, 0xc9, 0xb9, 0xea, 0xd4, 0xe7, 0xe0, 0xa1, 0xc0, 0xdb,
	0x35, 0x3a, 0x3b, 0xdf, 0x29, 0x10, 0xb3, 0x92, 0x75, 0xae, 0x48, 0xb7,
	0x56, 0x01, 0x59, 0x81, 0x85, 0x0d, 0x27, 0xdb, 0x67, 0x34, 0xe3, 0x7f,
	0x67, 0x21, 0x22, 0x67, 0xdd, 0x05, 0xee, 0xff, 0x27, 0xb9, 0xe7, 0xa8,
	0x13, 0xfa, 0x57, 0x4b, 0x72, 0xa0, 0x0b, 0x43, 0x0b,
};

static const uint8_t TH_4[] = {
	0x0e, 0xb8, 0x68, 0xf2, 0x63, 0xcf, 0x35, 0x55, 0xdc, 0xcd, 0x39,
	0x6d, 0xd8, 0xde, 0xc2, 0x9d, 0x37, 0x50, 0xd5, 0x99, 0xbe, 0x42,
	0xd5, 0xa4, 0x1a, 0x5a, 0x37, 0xc8, 0x96, 0xf2, 0x94, 0xac,
};

/**
 * \brief EDHOC message 4.
 */

static const uint8_t A_4[] = {
	0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40, 0x58,
	0x20, 0x0e, 0xb8, 0x68, 0xf2, 0x63, 0xcf, 0x35, 0x55, 0xdc, 0xcd, 0x39,
	0x6d, 0xd8, 0xde, 0xc2, 0x9d, 0x37, 0x50, 0xd5, 0x99, 0xbe, 0x42, 0xd5,
	0xa4, 0x1a, 0x5a, 0x37, 0xc8, 0x96, 0xf2, 0x94, 0xac,
};

static const uint8_t K_4_info[] = {
	0x08, 0x58, 0x20, 0x0e, 0xb8, 0x68, 0xf2, 0x63, 0xcf, 0x35, 0x55, 0xdc,
	0xcd, 0x39, 0x6d, 0xd8, 0xde, 0xc2, 0x9d, 0x37, 0x50, 0xd5, 0x99, 0xbe,
	0x42, 0xd5, 0xa4, 0x1a, 0x5a, 0x37, 0xc8, 0x96, 0xf2, 0x94, 0xac, 0x10,
};

static const uint8_t K_4[] = {
	0xdf, 0x8c, 0xb5, 0x86, 0x1e, 0x1f, 0xdf, 0xed,
	0xd3, 0xb2, 0x30, 0x15, 0xa3, 0x9d, 0x1e, 0x2e,
};

static const uint8_t IV_4_info[] = {

	0x09, 0x58, 0x20, 0x0e, 0xb8, 0x68, 0xf2, 0x63, 0xcf, 0x35, 0x55, 0xdc,
	0xcd, 0x39, 0x6d, 0xd8, 0xde, 0xc2, 0x9d, 0x37, 0x50, 0xd5, 0x99, 0xbe,
	0x42, 0xd5, 0xa4, 0x1a, 0x5a, 0x37, 0xc8, 0x96, 0xf2, 0x94, 0xac, 0x0d,
};

static const uint8_t IV_4[] = {
	0x12, 0x8e, 0xc6, 0x58, 0xd9, 0x70, 0xd7,
	0x38, 0x0f, 0x74, 0xfc, 0x6c, 0x27,
};

static const uint8_t CIPHERTEXT_4[] = {
	0x4f, 0x0e, 0xde, 0xe3, 0x66, 0xe5, 0xc8, 0x83,
};

static const uint8_t message_4[] = {
	0x48, 0x4f, 0x0e, 0xde, 0xe3, 0x66, 0xe5, 0xc8, 0x83,
};

/**
 * \brief PRK_out 
 */

static const uint8_t PRK_out_info[] = {
	0x07, 0x58, 0x20, 0x0e, 0xb8, 0x68, 0xf2, 0x63, 0xcf, 0x35,
	0x55, 0xdc, 0xcd, 0x39, 0x6d, 0xd8, 0xde, 0xc2, 0x9d, 0x37,
	0x50, 0xd5, 0x99, 0xbe, 0x42, 0xd5, 0xa4, 0x1a, 0x5a, 0x37,
	0xc8, 0x96, 0xf2, 0x94, 0xac, 0x18, 0x20,
};

static const uint8_t PRK_out[] = {
	0xb7, 0x44, 0xcb, 0x7d, 0x8a, 0x87, 0xcc, 0x04, 0x47, 0xc3, 0x35,
	0x0e, 0x16, 0x5b, 0x25, 0x0d, 0xab, 0x12, 0xec, 0x45, 0x33, 0x25,
	0xab, 0xb9, 0x22, 0xb3, 0x03, 0x07, 0xe5, 0xc3, 0x68, 0xf0,
};

static const uint8_t PRK_exporter_info[] = {
	0x0a,
	0x40,
	0x18,
	0x20,
};

static const uint8_t PRK_exporter[] = {
	0x2a, 0xae, 0xc8, 0xfc, 0x4a, 0xb3, 0xbc, 0x32, 0x95, 0xde, 0xf6,
	0xb5, 0x51, 0x05, 0x1a, 0x2f, 0xa5, 0x61, 0x42, 0x4d, 0xb3, 0x01,
	0xfa, 0x84, 0xf6, 0x42, 0xf5, 0x57, 0x8a, 0x6d, 0xf5, 0x1a,
};

/**
 * \brief OSCORE security session. 
 */

static const uint8_t OSCORE_Master_Secret_info[] = {
	0x00,
	0x40,
	0x10,
};

static const uint8_t OSCORE_Master_Secret[] = {
	0x1e, 0x1c, 0x6b, 0xea, 0xc3, 0xa8, 0xa1, 0xca,
	0xc4, 0x35, 0xde, 0x7e, 0x2f, 0x9a, 0xe7, 0xff,
};

static const uint8_t OSCORE_Master_Salt_info[] = {
	0x01,
	0x40,
	0x08,
};

static const uint8_t OSCORE_Master_Salt[] = {
	0xce, 0x7a, 0xb8, 0x44, 0xc0, 0x10, 0x6d, 0x73,
};

/**
 * \brief OSCORE security session after EDHOC key update.
 */

static const uint8_t keyUpdate_context[] = {
	0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea,
	0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c,
};

static const uint8_t keyUpdate_PRK_out[] = {
	0xda, 0x6e, 0xac, 0xd9, 0xa9, 0x85, 0xf4, 0xfb, 0xa9, 0xae, 0xc2,
	0xa9, 0x29, 0x90, 0x22, 0x97, 0x6b, 0x25, 0xb1, 0x4e, 0x89, 0xfa,
	0x15, 0x97, 0x94, 0xf2, 0x8d, 0x82, 0xfa, 0xf2, 0xda, 0xad,
};

static const uint8_t keyUpdate_PRK_exporter[] = {
	0x00, 0x14, 0xd2, 0x52, 0x5e, 0xe0, 0xd8, 0xe2, 0x13, 0xea, 0x59,
	0x08, 0x02, 0x8e, 0x9a, 0x1c, 0xe9, 0xa0, 0x1c, 0x30, 0x54, 0x6f,
	0x09, 0x30, 0xc0, 0x44, 0xd3, 0x8d, 0xb5, 0x36, 0x2c, 0x05,
};

static const uint8_t keyUpdate_OSCORE_Master_Secret[] = {
	0xee, 0x0f, 0xf5, 0x42, 0xc4, 0x7e, 0xb0, 0xe0,
	0x9c, 0x69, 0x30, 0x76, 0x49, 0xbd, 0xbb, 0xe5,
};

static const uint8_t keyUpdate_OSCORE_Master_Salt[] = {
	0x80, 0xce, 0xde, 0x2a, 0x1e, 0x5a, 0xab, 0x48,
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

#endif /* TEST_VECTOR_RFC9529_CHAPTER_2_H */
