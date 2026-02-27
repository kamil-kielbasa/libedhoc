/**
 * \file    test_common.h
 * \author  Kamil Kielbasa
 * \brief   Common includes, defines, and macros for all tests.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

/* Standard library headers */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* PSA crypto header */
#include <psa/crypto.h>

/* Unity headers */
#include <unity.h>
#include <unity_fixture.h>

/* Common test constants */
#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)
#define DH_KEY_AGREEMENT_LENGTH (32)
#define ENTROPY_LENGTH (16)

#endif /* TEST_COMMON_H */
