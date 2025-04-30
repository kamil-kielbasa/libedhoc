/**
 * \file    test_vector_draft_edhoc_psk.h
 * \author  Kamil Kielbasa
 * \brief   Example test vector for EDHOC-PSK (draft-ietf-lake-edhoc-psk-03)
 *          
 * \version 1.0
 * \date    2025-04-24
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_VECTOR_DRAFT_EDHOC_PSK_H
#define TEST_VECTOR_DRAFT_EDHOC_PSK_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

static const uint8_t METHOD = 4;

static const int32_t SUITES[] = { 0x02 };

static const uint8_t C_I[] = { -14 };

static const uint8_t C_R[] = { 24 };

/*
 * {                                              /CCS/
 *   2 : "mydotbot",                              /sub/
 *   8 : {                                        /cnf/
 *     1 : {                                      /COSE_Key/
 *       1 : 4,                                   /kty/
 *       2 : h'0f',                               /kid/
 *      -1 : h'50930FF462A77A3540CF546325DEA214'  /k/
 *   }
 * }
 */

/* ID_CRED_PSK: */
static const int32_t ID_CRED_PSK_raw = 0x15;
static const uint8_t ID_CRED_PSK_raw_cborised[] = { 0x0f };
static const uint8_t ID_CRED_PSK_cborised[] = { 0xa1, 0x04, 0x41, 0x0f };

/* CRED_PSK: */
static const uint8_t CRED_PSK_cborised[] = {
	0xA2, 0x02, 0x68, 0x6D, 0x79, 0x64, 0x6F, 0x74, 0x62, 0x6F,
	0x74, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x0F,
	0x20, 0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35,
	0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};
static const uint8_t CRED_PSK_raw_key[] = {
	0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35,
	0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};

/* OSCORE master key & salt lengths: */
static const size_t oscore_master_secret_length = 16;
static const size_t oscore_master_salt_length = 8;

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* TEST_VECTOR_DRAFT_EDHOC_PSK_H */
