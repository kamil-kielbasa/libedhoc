/**
 * \file    edhoc_kdf_kmac256_xkcp.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC KMAC256 KDF backed by the XKCP SP800-185 implementation.
 *
 *          This delegates EDHOC_Extract / EDHOC_Expand to the upstream,
 *          KAT-validated KMAC256() from the eXtended Keccak Code Package
 *          (XKCP, SP800-185). No NIST SP 800-185 encoding is re-implemented
 *          here and no Keccak internals are touched.
 *
 *          Build wiring (the CMake ExternalProject that builds libXKCP and
 *          exposes SP800-185.h) lives in externals/CMakeLists.txt.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

#include "edhoc_kdf_kmac256.h"

#include <stdint.h>
#include <stddef.h>

#include "edhoc_values.h"
#include "edhoc_macros.h"
#include "edhoc_backend_log.h"

/* XKCP SP800-185 public API (KMAC128/256, cSHAKE128/256). */
#include "SP800-185.h"

/* Module interface function definitions ----------------------------------- */

int edhoc_kdf_kmac256(const uint8_t *key, size_t key_length,
		      const uint8_t *input, size_t input_length,
		      uint8_t *output, size_t output_length)
{
	if (NULL == key || NULL == output || 0 == output_length ||
	    (NULL == input && 0 != input_length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/*
	 * RFC 9528 Section 4.1: EDHOC_Extract/Expand for the SHAKE256 suite are
	 * KMAC256 with an EMPTY customization string S = "".
	 *
	 * XKCP KMAC256() takes bit lengths and returns 0 on success. All EDHOC
	 * inputs are whole-byte strings, so every length is a multiple of 8.
	 */
	const int rc = KMAC256(
		(const BitSequence *)key, (BitLength)key_length * 8u,
		(const BitSequence *)input, (BitLength)input_length * 8u,
		(BitSequence *)output, (BitLength)output_length * 8u,
		/* customization S = "" */ (const BitSequence *)"",
		(BitLength)0u);

	if (0 != rc) {
		EDHOC_LOG_ERR("XKCP KMAC256 failed: %d", rc);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}
