/**
 * \file    internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Shared fixtures for internals unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */

const struct edhoc_keys *internals_keys;
const struct edhoc_crypto *internals_crypto;

/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void internals_setup_crypto_context(struct edhoc_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	edhoc_context_init(ctx);

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(ctx, method, 1);

	edhoc_set_cipher_suites(ctx, edhoc_cipher_suite_0_get_suite(), 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	edhoc_set_connection_id(ctx, &cid);

	edhoc_bind_keys(ctx, internals_keys);
	edhoc_bind_crypto(ctx, internals_crypto);
}
