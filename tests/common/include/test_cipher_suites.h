/**
 * \file    test_cipher_suites.h
 * \author  Kamil Kielbasa
 * \brief   Shared cipher suite definitions for tests.
 *
 *          Provides pre-configured cipher suite structs so that every
 *          test file does not have to repeat the same 8-field initializer.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 *
 */

#ifndef TEST_CIPHER_SUITES_H
#define TEST_CIPHER_SUITES_H

#include <edhoc.h>

extern const struct edhoc_cipher_suite test_cipher_suite_0;
extern const struct edhoc_cipher_suite test_cipher_suite_2;

#endif /* TEST_CIPHER_SUITES_H */
