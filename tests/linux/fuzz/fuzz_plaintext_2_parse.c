/**
 * \file    fuzz_plaintext_2_parse.c
 * \author  Kamil Kielbasa
 * \brief   libFuzzer harness feeding arbitrary input to parse_plaintext_2().
 *
 *          fuzz_message_2_process has to decrypt CIPHERTEXT_2 before it can
 *          parse anything, and mutated bytes never decrypt into valid CBOR, so
 *          that target never reaches this parser. Here the plaintext is passed
 *          in directly.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_plaintext_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/** Library-internal parser under test, exposed by LIBEDHOC_TESTS. */
extern int parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt);

/* Static variables and constants ------------------------------------------ */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (0 == size) {
		return 0;
	}

	/* The parser touches neither crypto nor the key store, so a zeroed
	 * context is a complete environment for it. */
	struct edhoc_context ctx = { 0 };
	struct plaintext parsed_ptxt = { 0 };

	(void)parse_plaintext_2(&ctx, data, size, &parsed_ptxt);

	return 0;
}
