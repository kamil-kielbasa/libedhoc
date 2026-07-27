/**
 * \file    test_platform.h
 * \author  Kamil Kielbasa
 * \brief   Shared platform interface for the test suite.
 *
 *          Every EDHOC context must have a platform bound (a \c zeroize) before
 *          the message API will run. This header provides a ready-made platform
 *          implementation; tests bind it explicitly with
 *          \c edhoc_bind_platform(ctx, test_get_platform()), mirroring how they
 *          bind the crypto interface via \c edhoc_cipher_suite_N_get_crypto().
 *
 * \copyright Copyright (c) 2026
 */

#ifndef TEST_PLATFORM_H
#define TEST_PLATFORM_H

/* Standard library headers */
#include <stddef.h>
#include <string.h>

/* EDHOC public API (platform interface). */
#include <edhoc/edhoc.h>

/**
 * \brief Memory wipe for tests.
 *
 * The test suite runs under sanitizers and Valgrind rather than an optimizer
 * that may elide a plain wipe, so \c memset is enough here; production code
 * must still supply a non-elidable \c zeroize.
 */
static inline void test_platform_zeroize(void *buffer, size_t length)
{
	memset(buffer, 0, length);
}

/**
 * \brief Shared test platform interface.
 *
 * Mirrors \c edhoc_cipher_suite_N_get_crypto(): tests bind it explicitly via
 * \c edhoc_bind_platform(ctx, test_get_platform()).
 *
 * \return Pointer to the shared, immutable platform interface.
 */
static inline const struct edhoc_platform *test_get_platform(void)
{
	static const struct edhoc_platform platform = {
		.zeroize = test_platform_zeroize,
	};

	return &platform;
}

#endif /* TEST_PLATFORM_H */
