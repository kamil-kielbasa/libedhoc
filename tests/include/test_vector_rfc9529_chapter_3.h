/**
 * \file    test_vector_rfc9529_chapter_3.h
 * \author  Kamil Kielbasa
 * \brief   Test vector from EDHOC traces (RFC 9529) for chapter 3.
 *          It contains authentication with ephemeral-static Diffie-Hellman
 *          represented as raw public keys (RPKs), encoded in a CWT Claims Set (CCS)
 *          and identified by the COSE header parameter 'kid'.
 *          
 * \version 0.6
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_VECTOR_RFC9529_CHAPTER_3_H
#define TEST_VECTOR_RFC9529_CHAPTER_3_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

/**
 * \brief EDHOC message 1.
 */

static const uint8_t METHOD = 3;

static const uint8_t SUITES_I[] = { 0x82, 0x06, 0x02 };

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

static const uint8_t message_1[] = {
	0x03, 0x82, 0x06, 0x02, 0x58, 0x20, 0x8a, 0xf6, 0xf4, 0x30,
	0xeb, 0xe1, 0x8d, 0x34, 0x18, 0x40, 0x17, 0xa9, 0xa1, 0x1b,
	0xf5, 0x11, 0xc8, 0xdf, 0xf8, 0xf8, 0x34, 0x73, 0x0b, 0x96,
	0xc1, 0xb7, 0xc8, 0xdb, 0xca, 0x2f, 0xc3, 0xb6, 0x37,
};

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

static const uint8_t H_message_1[] = {
	0xca, 0x02, 0xca, 0xbd, 0xa5, 0xa8, 0x90, 0x27, 0x49, 0xb4, 0x2f,
	0x71, 0x10, 0x50, 0xbb, 0x4d, 0xbd, 0x52, 0x15, 0x3e, 0x87, 0x52,
	0x75, 0x94, 0xb3, 0x9f, 0x50, 0xcd, 0xf0, 0x19, 0x88, 0x8c,
};

static const uint8_t TH_2[] = {
	0x35, 0x6e, 0xfd, 0x53, 0x77, 0x14, 0x25, 0xe0, 0x08, 0xf3, 0xfe,
	0x3a, 0x86, 0xc8, 0x3f, 0xf4, 0xc6, 0xb1, 0x6e, 0x57, 0x02, 0x8f,
	0xf3, 0x9d, 0x52, 0x36, 0xc1, 0x82, 0xb2, 0x02, 0x08, 0x4b,
};

static const uint8_t G_XY[] = {
	0x2f, 0x0c, 0xb7, 0xe8, 0x60, 0xba, 0x53, 0x8f, 0xbf, 0x5c, 0x8b,
	0xde, 0xd0, 0x09, 0xf6, 0x25, 0x9b, 0x4b, 0x62, 0x8f, 0xe1, 0xeb,
	0x7d, 0xbe, 0x93, 0x78, 0xe5, 0xec, 0xf7, 0xa8, 0x24, 0xba,
};

static const uint8_t PRK_2e[] = {
	0x5a, 0xa0, 0xd6, 0x9f, 0x3e, 0x3d, 0x1e, 0x0c, 0x47, 0x9f, 0x0b,
	0x8a, 0x48, 0x66, 0x90, 0xc9, 0x80, 0x26, 0x30, 0xc3, 0x46, 0x6b,
	0x1d, 0xc9, 0x23, 0x71, 0xc9, 0x82, 0x56, 0x31, 0x70, 0xb5,
};

static const uint8_t SK_R[] = {
	0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31,
	0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03,
	0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac,
};

static const uint8_t PK_R[] = {
	0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c,
	0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a,
	0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
};

static const uint8_t SALT_3e2m_info[] = {
	0x01, 0x58, 0x20, 0x35, 0x6e, 0xfd, 0x53, 0x77, 0x14, 0x25,
	0xe0, 0x08, 0xf3, 0xfe, 0x3a, 0x86, 0xc8, 0x3f, 0xf4, 0xc6,
	0xb1, 0x6e, 0x57, 0x02, 0x8f, 0xf3, 0x9d, 0x52, 0x36, 0xc1,
	0x82, 0xb2, 0x02, 0x08, 0x4b, 0x18, 0x20,
};

static const uint8_t SALT_3e2m[] = {
	0xaf, 0x4e, 0x10, 0x3a, 0x47, 0xcb, 0x3c, 0xf3, 0x25, 0x70, 0xd5,
	0xc2, 0x5a, 0xd2, 0x77, 0x32, 0xbd, 0x8d, 0x81, 0x78, 0xe9, 0xa6,
	0x9d, 0x06, 0x1c, 0x31, 0xa2, 0x7f, 0x8e, 0x3c, 0xa9, 0x26,
};

static const uint8_t G_RX[] = {
	0xf2, 0xb6, 0xee, 0xa0, 0x22, 0x20, 0xb9, 0x5e, 0xee, 0x5a, 0x0b,
	0xc7, 0x01, 0xf0, 0x74, 0xe0, 0x0a, 0x84, 0x3e, 0xa0, 0x24, 0x22,
	0xf6, 0x08, 0x25, 0xfb, 0x26, 0x9b, 0x3e, 0x16, 0x14, 0x23,
};

static const uint8_t PRK_3e2m[] = {
	0x0c, 0xa3, 0xd3, 0x39, 0x82, 0x96, 0xb3, 0xc0, 0x39, 0x00, 0x98,
	0x76, 0x20, 0xc1, 0x1f, 0x6f, 0xce, 0x70, 0x78, 0x1c, 0x1d, 0x12,
	0x19, 0x72, 0x0f, 0x9e, 0xc0, 0x8c, 0x12, 0x2d, 0x84, 0x34,
};

static const int32_t ID_CRED_R_raw = -19;

static const uint8_t ID_CRED_R_raw_cborised[] = { 0x32 };

static const uint8_t ID_CRED_R_cborised[] = { 0xa1, 0x04, 0x41, 0x32 };

static const uint8_t CRED_R_cborised[] = {
	0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65,
	0x64, 0x75, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20,
	0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3,
	0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
	0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
	0x22, 0x58, 0x20, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2,
	0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f,
	0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
};

static const uint8_t context_2[] = {
	0x27, 0xa1, 0x04, 0x41, 0x32, 0x58, 0x20, 0x35, 0x6e, 0xfd, 0x53, 0x77,
	0x14, 0x25, 0xe0, 0x08, 0xf3, 0xfe, 0x3a, 0x86, 0xc8, 0x3f, 0xf4, 0xc6,
	0xb1, 0x6e, 0x57, 0x02, 0x8f, 0xf3, 0x9d, 0x52, 0x36, 0xc1, 0x82, 0xb2,
	0x02, 0x08, 0x4b, 0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
	0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02,
	0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60, 0x52,
	0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd,
	0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46,
	0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b,
	0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a,
	0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf,
	0x60, 0x72,
};

static const uint8_t MAC_2_info_cborised[] = {
	0x02, 0x58, 0x86, 0x27, 0xa1, 0x04, 0x41, 0x32, 0x58, 0x20, 0x35, 0x6e,
	0xfd, 0x53, 0x77, 0x14, 0x25, 0xe0, 0x08, 0xf3, 0xfe, 0x3a, 0x86, 0xc8,
	0x3f, 0xf4, 0xc6, 0xb1, 0x6e, 0x57, 0x02, 0x8f, 0xf3, 0x9d, 0x52, 0x36,
	0xc1, 0x82, 0xb2, 0x02, 0x08, 0x4b, 0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1, 0x01, 0xa5,
	0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3,
	0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23,
	0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93,
	0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xe2,
	0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3,
	0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c,
	0x51, 0xea, 0xbf, 0x60, 0x72, 0x08,
};

static const uint8_t MAC_2[] = {
	0x09, 0x43, 0x30, 0x5c, 0x89, 0x9f, 0x5c, 0x54,
};

static const uint8_t Signature_or_MAC_2[] = {
	0x09, 0x43, 0x30, 0x5c, 0x89, 0x9f, 0x5c, 0x54,
};

static const uint8_t PLAINTEXT_2[] = {
	0x27, 0x32, 0x48, 0x09, 0x43, 0x30, 0x5c, 0x89, 0x9f, 0x5c, 0x54,
};

static const uint8_t KEYSTREAM_2_info[] = {
	0x00, 0x58, 0x20, 0x35, 0x6e, 0xfd, 0x53, 0x77, 0x14, 0x25, 0xe0, 0x08,
	0xf3, 0xfe, 0x3a, 0x86, 0xc8, 0x3f, 0xf4, 0xc6, 0xb1, 0x6e, 0x57, 0x02,
	0x8f, 0xf3, 0x9d, 0x52, 0x36, 0xc1, 0x82, 0xb2, 0x02, 0x08, 0x4b, 0x0b,
};

static const uint8_t KEYSTERAM_2[] = {
	0xbf, 0x50, 0xe9, 0xe7, 0xba, 0xd0, 0xbb, 0x68, 0x17, 0x33, 0x99,
};

static const uint8_t CIPHERTEXT_2[] = {
	0x98, 0x62, 0xa1, 0xee, 0xf9, 0xe0, 0xe7, 0xe1, 0x88, 0x6f, 0xcd,
};

static const uint8_t message_2[] = {
	0x58, 0x2b, 0x41, 0x97, 0x01, 0xd7, 0xf0, 0x0a, 0x26, 0xc2, 0xdc, 0x58,
	0x7a, 0x36, 0xdd, 0x75, 0x25, 0x49, 0xf3, 0x37, 0x63, 0xc8, 0x93, 0x42,
	0x2c, 0x8e, 0xa0, 0xf9, 0x55, 0xa1, 0x3a, 0x4f, 0xf5, 0xd5, 0x98, 0x62,
	0xa1, 0xee, 0xf9, 0xe0, 0xe7, 0xe1, 0x88, 0x6f, 0xcd,
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
	0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03,
	0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96,
	0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
};

static const uint8_t TH_3_input[] = {
	0x58, 0x20, 0x35, 0x6e, 0xfd, 0x53, 0x77, 0x14, 0x25, 0xe0, 0x08, 0xf3,
	0xfe, 0x3a, 0x86, 0xc8, 0x3f, 0xf4, 0xc6, 0xb1, 0x6e, 0x57, 0x02, 0x8f,
	0xf3, 0x9d, 0x52, 0x36, 0xc1, 0x82, 0xb2, 0x02, 0x08, 0x4b, 0x27, 0x32,
	0x48, 0x09, 0x43, 0x30, 0x5c, 0x89, 0x9f, 0x5c, 0x54, 0xa2, 0x02, 0x6b,
	0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08,
	0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58,
	0x20, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c,
	0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb,
	0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20,
	0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09,
	0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10,
	0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
};

static const uint8_t TH_3[] = {
	0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0, 0x18, 0xf8,
	0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b, 0x25, 0x07, 0x03, 0x9d,
	0xf0, 0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3, 0x15, 0x5c,
};

static const uint8_t SALT_4e3m_info[] = {
	0x05, 0x58, 0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc,
	0x91, 0xe0, 0x18, 0xf8, 0x88, 0x27, 0x62, 0xa7, 0x22, 0x00,
	0x0b, 0x25, 0x07, 0x03, 0x9d, 0xf0, 0xbc, 0x1b, 0xbf, 0x0c,
	0x16, 0x1b, 0xb3, 0x15, 0x5c, 0x18, 0x20,
};

static const uint8_t SALT_4e3m[] = {
	0xcf, 0xdd, 0xf9, 0x51, 0x5a, 0x7e, 0x46, 0xe7, 0xb4, 0xdb, 0xff,
	0x31, 0xcb, 0xd5, 0x6c, 0xd0, 0x4b, 0xa3, 0x32, 0x25, 0x0d, 0xe9,
	0xea, 0x5d, 0xe1, 0xca, 0xf9, 0xf6, 0xd1, 0x39, 0x14, 0xa7,
};

static const uint8_t G_IY[] = {
	0x08, 0x0f, 0x42, 0x50, 0x85, 0xbc, 0x62, 0x49, 0x08, 0x9e, 0xac,
	0x8f, 0x10, 0x8e, 0xa6, 0x23, 0x26, 0x85, 0x7e, 0x12, 0xab, 0x07,
	0xd7, 0x20, 0x28, 0xca, 0x1b, 0x5f, 0x36, 0xe0, 0x04, 0xb3,
};

static const uint8_t PRK_4e3m[] = {
	0x81, 0xcc, 0x8a, 0x29, 0x8e, 0x35, 0x70, 0x44, 0xe3, 0xc4, 0x66,
	0xbb, 0x5c, 0x0a, 0x1e, 0x50, 0x7e, 0x01, 0xd4, 0x92, 0x38, 0xae,
	0xba, 0x13, 0x8d, 0xf9, 0x46, 0x35, 0x40, 0x7c, 0x0f, 0xf7,
};

static const int32_t ID_CRED_I_raw = -12;

static const uint8_t ID_CRED_I_raw_cborised[] = { 0x2b };

static const uint8_t ID_CRED_I_cborised[] = { 0xa1, 0x04, 0x41, 0x2b };

static const uint8_t CRED_I_cborised[] = {
	0xa2, 0x02, 0x77, 0x34, 0x32, 0x2d, 0x35, 0x30, 0x2d, 0x33, 0x31, 0x2d,
	0x46, 0x46, 0x2d, 0x45, 0x46, 0x2d, 0x33, 0x37, 0x2d, 0x33, 0x32, 0x2d,
	0x33, 0x39, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x2b, 0x20,
	0x01, 0x21, 0x58, 0x20, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc,
	0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16,
	0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
	0x22, 0x58, 0x20, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82,
	0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57,
	0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

static const uint8_t context_3[] = {
	0xa1, 0x04, 0x41, 0x2b, 0x58, 0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b,
	0xcc, 0x91, 0xe0, 0x18, 0xf8, 0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b,
	0x25, 0x07, 0x03, 0x9d, 0xf0, 0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3,
	0x15, 0x5c, 0xa2, 0x02, 0x77, 0x34, 0x32, 0x2d, 0x35, 0x30, 0x2d, 0x33,
	0x31, 0x2d, 0x46, 0x46, 0x2d, 0x45, 0x46, 0x2d, 0x33, 0x37, 0x2d, 0x33,
	0x32, 0x2d, 0x33, 0x39, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41,
	0x2b, 0x20, 0x01, 0x21, 0x58, 0x20, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5,
	0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47,
	0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f,
	0x7e, 0xb6, 0x22, 0x58, 0x20, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
	0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87,
	0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff,
	0xc8,
};

static const uint8_t MAC_3_info[] = {
	0x06, 0x58, 0x91, 0xa1, 0x04, 0x41, 0x2b, 0x58, 0x20, 0xad, 0xaf, 0x67,
	0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0, 0x18, 0xf8, 0x88, 0x27, 0x62, 0xa7,
	0x22, 0x00, 0x0b, 0x25, 0x07, 0x03, 0x9d, 0xf0, 0xbc, 0x1b, 0xbf, 0x0c,
	0x16, 0x1b, 0xb3, 0x15, 0x5c, 0xa2, 0x02, 0x77, 0x34, 0x32, 0x2d, 0x35,
	0x30, 0x2d, 0x33, 0x31, 0x2d, 0x46, 0x46, 0x2d, 0x45, 0x46, 0x2d, 0x33,
	0x37, 0x2d, 0x33, 0x32, 0x2d, 0x33, 0x39, 0x08, 0xa1, 0x01, 0xa5, 0x01,
	0x02, 0x02, 0x41, 0x2b, 0x20, 0x01, 0x21, 0x58, 0x20, 0xac, 0x75, 0xe9,
	0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22,
	0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c,
	0xb4, 0x30, 0x7f, 0x7e, 0xb6, 0x22, 0x58, 0x20, 0x6e, 0x5d, 0xe6, 0x11,
	0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb,
	0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21,
	0xff, 0x3a, 0xff, 0xc8, 0x08,
};

static const uint8_t MAC_3[] = {
	0x62, 0x3c, 0x91, 0xdf, 0x41, 0xe3, 0x4c, 0x2f,
};

static const uint8_t Signature_or_MAC_3[] = {
	0x62, 0x3c, 0x91, 0xdf, 0x41, 0xe3, 0x4c, 0x2f,
};

static const uint8_t PLAINTEXT_3[] = {
	0x2b, 0x48, 0x62, 0x3c, 0x91, 0xdf, 0x41, 0xe3, 0x4c, 0x2f,
};

static const uint8_t A_3[] = {
	0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40, 0x58,
	0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0, 0x18, 0xf8,
	0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b, 0x25, 0x07, 0x03, 0x9d, 0xf0,
	0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3, 0x15, 0x5c,
};

static const uint8_t K_3_info[] = {
	0x03, 0x58, 0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0,
	0x18, 0xf8, 0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b, 0x25, 0x07, 0x03,
	0x9d, 0xf0, 0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3, 0x15, 0x5c, 0x10,
};

static const uint8_t K_3[] = {
	0x8e, 0x7a, 0x30, 0x04, 0x20, 0x00, 0xf7, 0x90,
	0x0e, 0x81, 0x74, 0x13, 0x1f, 0x75, 0xf3, 0xed,
};

static const uint8_t IV_3_info[] = {
	0x04, 0x58, 0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0,
	0x18, 0xf8, 0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b, 0x25, 0x07, 0x03,
	0x9d, 0xf0, 0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3, 0x15, 0x5c, 0x0d,
};

static const uint8_t IV_3[] = {
	0x6d, 0x83, 0x00, 0xc1, 0xe2, 0x3b, 0x56,
	0x15, 0x3a, 0xe7, 0x0e, 0xe4, 0x57,
};

static const uint8_t CIPHERTEXT_3[] = {
	0xe5, 0x62, 0x09, 0x7b, 0xc4, 0x17, 0xdd, 0x59, 0x19,
	0x48, 0x5a, 0xc7, 0x89, 0x1f, 0xfd, 0x90, 0xa9, 0xfc,
};

static const uint8_t message_3[] = {
	0x52, 0xe5, 0x62, 0x09, 0x7b, 0xc4, 0x17, 0xdd, 0x59, 0x19,
	0x48, 0x5a, 0xc7, 0x89, 0x1f, 0xfd, 0x90, 0xa9, 0xfc,
};

static const uint8_t TH_4_input[] = {
	0x58, 0x20, 0xad, 0xaf, 0x67, 0xa7, 0x8a, 0x4b, 0xcc, 0x91, 0xe0, 0x18,
	0xf8, 0x88, 0x27, 0x62, 0xa7, 0x22, 0x00, 0x0b, 0x25, 0x07, 0x03, 0x9d,
	0xf0, 0xbc, 0x1b, 0xbf, 0x0c, 0x16, 0x1b, 0xb3, 0x15, 0x5c, 0x2b, 0x48,
	0x62, 0x3c, 0x91, 0xdf, 0x41, 0xe3, 0x4c, 0x2f, 0xa2, 0x02, 0x77, 0x34,
	0x32, 0x2d, 0x35, 0x30, 0x2d, 0x33, 0x31, 0x2d, 0x46, 0x46, 0x2d, 0x45,
	0x46, 0x2d, 0x33, 0x37, 0x2d, 0x33, 0x32, 0x2d, 0x33, 0x39, 0x08, 0xa1,
	0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x2b, 0x20, 0x01, 0x21, 0x58, 0x20,
	0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99,
	0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a,
	0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6, 0x22, 0x58, 0x20, 0x6e,
	0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7,
	0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a,
	0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

static const uint8_t TH_4[] = {
	0xc9, 0x02, 0xb1, 0xe3, 0xa4, 0x32, 0x6c, 0x93, 0xc5, 0x55, 0x1f,
	0x5f, 0x3a, 0xa6, 0xc5, 0xec, 0xc0, 0x24, 0x68, 0x06, 0x76, 0x56,
	0x12, 0xe5, 0x2b, 0x5d, 0x99, 0xe6, 0x05, 0x9d, 0x6b, 0x6e,
};

/**
 * \brief EDHOC message 4.
 */

static const uint8_t A_4[] = {
	0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40, 0x58,
	0x20, 0xc9, 0x02, 0xb1, 0xe3, 0xa4, 0x32, 0x6c, 0x93, 0xc5, 0x55, 0x1f,
	0x5f, 0x3a, 0xa6, 0xc5, 0xec, 0xc0, 0x24, 0x68, 0x06, 0x76, 0x56, 0x12,
	0xe5, 0x2b, 0x5d, 0x99, 0xe6, 0x05, 0x9d, 0x6b, 0x6e,
};

static const uint8_t K_4_info[] = {
	0x08, 0x58, 0x20, 0xc9, 0x02, 0xb1, 0xe3, 0xa4, 0x32, 0x6c, 0x93, 0xc5,
	0x55, 0x1f, 0x5f, 0x3a, 0xa6, 0xc5, 0xec, 0xc0, 0x24, 0x68, 0x06, 0x76,
	0x56, 0x12, 0xe5, 0x2b, 0x5d, 0x99, 0xe6, 0x05, 0x9d, 0x6b, 0x6e, 0x10,
};

static const uint8_t K_4[] = {
	0xd3, 0xc7, 0x78, 0x72, 0xb6, 0xee, 0xb5, 0x08,
	0x91, 0x1b, 0xdb, 0xd3, 0x08, 0xb2, 0xe6, 0xa0,
};

static const uint8_t IV_4_info[] = {
	0x09, 0x58, 0x20, 0xc9, 0x02, 0xb1, 0xe3, 0xa4, 0x32, 0x6c, 0x93, 0xc5,
	0x55, 0x1f, 0x5f, 0x3a, 0xa6, 0xc5, 0xec, 0xc0, 0x24, 0x68, 0x06, 0x76,
	0x56, 0x12, 0xe5, 0x2b, 0x5d, 0x99, 0xe6, 0x05, 0x9d, 0x6b, 0x6e, 0x0d,
};

static const uint8_t IV_4[] = {
	0x04, 0xff, 0x0f, 0x44, 0x45, 0x6e, 0x96,
	0xe2, 0x17, 0x85, 0x3c, 0x36, 0x01,
};

static const uint8_t CIPHERTEXT_4[] = {
	0x28, 0xc9, 0x66, 0xb7, 0xca, 0x30, 0x4f, 0x83,
};

static const uint8_t message_4[] = {
	0x48, 0x28, 0xc9, 0x66, 0xb7, 0xca, 0x30, 0x4f, 0x83,
};

/**
 * \brief PRK_out.
 */

static const uint8_t PRK_out_info[] = {
	0x07, 0x58, 0x20, 0xc9, 0x02, 0xb1, 0xe3, 0xa4, 0x32, 0x6c,
	0x93, 0xc5, 0x55, 0x1f, 0x5f, 0x3a, 0xa6, 0xc5, 0xec, 0xc0,
	0x24, 0x68, 0x06, 0x76, 0x56, 0x12, 0xe5, 0x2b, 0x5d, 0x99,
	0xe6, 0x05, 0x9d, 0x6b, 0x6e, 0x18, 0x20,
};

static const uint8_t PRK_out[] = {
	0x2c, 0x71, 0xaf, 0xc1, 0xa9, 0x33, 0x8a, 0x94, 0x0b, 0xb3, 0x52,
	0x9c, 0xa7, 0x34, 0xb8, 0x86, 0xf3, 0x0d, 0x1a, 0xba, 0x0b, 0x4d,
	0xc5, 0x1b, 0xee, 0xae, 0xab, 0xdf, 0xea, 0x9e, 0xcb, 0xf8,
};

static const uint8_t PRK_exporter_info[] = {
	0x0a,
	0x40,
	0x18,
	0x20,
};

static const uint8_t PRK_exporter[] = {
	0xe1, 0x4d, 0x06, 0x69, 0x9c, 0xee, 0x24, 0x8c, 0x5a, 0x04, 0xbf,
	0x92, 0x27, 0xbb, 0xcd, 0x4c, 0xe3, 0x94, 0xde, 0x7d, 0xcb, 0x56,
	0xdb, 0x43, 0x55, 0x54, 0x74, 0x17, 0x1e, 0x64, 0x46, 0xdb,
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
	0xf9, 0x86, 0x8f, 0x6a, 0x3a, 0xca, 0x78, 0xa0,
	0x5d, 0x14, 0x85, 0xb3, 0x50, 0x30, 0xb1, 0x62,
};

static const uint8_t OSCORE_Master_Salt_info[] = {
	0x01,
	0x40,
	0x08,
};

static const uint8_t OSCORE_Master_Salt[] = {
	0xad, 0xa2, 0x4c, 0x7d, 0xbf, 0xc8, 0x5e, 0xeb,
};

/**
 * \brief OSCORE security session after EDHOC key update.
 */

static const uint8_t keyUpdate_context[] = {
	0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c,
	0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea,
};

static const uint8_t keyUpdate_PRK_out[] = {
	0xf9, 0x79, 0x53, 0x77, 0x43, 0xfe, 0x0b, 0xd6, 0xb9, 0xb1, 0x41,
	0xdd, 0xbd, 0x79, 0x65, 0x6c, 0x52, 0xe6, 0xdc, 0x7c, 0x50, 0xad,
	0x80, 0x77, 0x54, 0xd7, 0x4d, 0x07, 0xe8, 0x7d, 0x0d, 0x16,
};

static const uint8_t keyUpdate_PRK_exporter[] = {
	0x00, 0xfc, 0xf7, 0xdb, 0x9b, 0x2e, 0xad, 0x73, 0x82, 0x4e, 0x7e,
	0x83, 0x03, 0x63, 0xc8, 0x05, 0xc2, 0x96, 0xf9, 0x02, 0x83, 0x0f,
	0xac, 0x23, 0xd8, 0x6c, 0x35, 0x9c, 0x75, 0x2f, 0x0f, 0x17,
};

static const uint8_t keyUpdate_OSCORE_Master_Secret[] = {
	0x49, 0xf7, 0x2f, 0xac, 0x02, 0xb4, 0x65, 0x8b,
	0xda, 0x21, 0xe2, 0xda, 0xc6, 0x6f, 0xc3, 0x74,
};

static const uint8_t keyUpdate_OSCORE_Master_Salt[] = {
	0xdd, 0x8b, 0x24, 0xf2, 0xaa, 0x9b, 0x01, 0x1a,
};

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* TEST_VECTOR_RFC9529_CHAPTER_3_H */
