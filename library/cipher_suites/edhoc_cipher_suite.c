/**
 * \file    edhoc_cipher_suite.c
 * \author  Kamil Kielbasa
 * \brief   Enum-based cipher-suite getters dispatching to the reference suites.
 *
 *          These replace the per-suite \c edhoc_cipher_suite_N_get_* getters as
 *          the recommended entry point: a single pair of functions keyed by
 *          \ref edhoc_cipher_suite_id.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC public headers: */
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>

/* Reference cipher-suite headers (only those enabled at build time): */
#if CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE
#include "edhoc_cipher_suite_0.h"
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE
#include "edhoc_cipher_suite_2.h"
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE
#include "edhoc_cipher_suite_4.h"
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE
#include "edhoc_cipher_suite_24.h"
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
#include "edhoc_cipher_suite_pqc_1.h"
#endif

/* Module interface function definitions ----------------------------------- */

const struct edhoc_cipher_suite *
edhoc_cipher_suite_get_params(enum edhoc_cipher_suite_id id)
{
	switch (id) {
#if CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE
	case EDHOC_CIPHER_SUITE_0:
		return edhoc_cipher_suite_0_get_suite();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE
	case EDHOC_CIPHER_SUITE_2:
		return edhoc_cipher_suite_2_get_suite();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE
	case EDHOC_CIPHER_SUITE_4:
		return edhoc_cipher_suite_4_get_suite();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE
	case EDHOC_CIPHER_SUITE_24:
		return edhoc_cipher_suite_24_get_suite();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
	case EDHOC_CIPHER_SUITE_PQC_1:
		return edhoc_cipher_suite_pqc_1_get_suite();
#endif
	default:
		/* A disabled suite is not compiled in; unknown ids are
		 * rejected. */
		return NULL;
	}
}

const struct edhoc_crypto *
edhoc_cipher_suite_get_crypto(enum edhoc_cipher_suite_id id)
{
	switch (id) {
#if CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE
	case EDHOC_CIPHER_SUITE_0:
		return edhoc_cipher_suite_0_get_crypto();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE
	case EDHOC_CIPHER_SUITE_2:
		return edhoc_cipher_suite_2_get_crypto();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE
	case EDHOC_CIPHER_SUITE_4:
		return edhoc_cipher_suite_4_get_crypto();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE
	case EDHOC_CIPHER_SUITE_24:
		return edhoc_cipher_suite_24_get_crypto();
#endif
#if CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
	case EDHOC_CIPHER_SUITE_PQC_1:
		return edhoc_cipher_suite_pqc_1_get_crypto();
#endif
	default:
		/* A disabled suite is not compiled in; unknown ids are
		 * rejected. */
		return NULL;
	}
}
