/**
 * \file    edhoc_key_slot_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC key-store handle slots implementation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_key_slot_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

const void *edhoc_key_slot_id(const struct edhoc_context *ctx,
			      enum edhoc_key_slot_id slot)
{
	return ctx->key_slots[slot].key_id;
}

void *edhoc_key_slot_id_mut(struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot)
{
	return ctx->key_slots[slot].key_id;
}

bool edhoc_key_slot_present(const struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot)
{
	return ctx->key_slots[slot].present;
}

void edhoc_key_slot_mark_present(struct edhoc_context *ctx,
				 enum edhoc_key_slot_id slot)
{
	ctx->key_slots[slot].present = true;
}

void edhoc_key_slot_move(struct edhoc_context *ctx,
			 enum edhoc_key_slot_id dst_slot,
			 enum edhoc_key_slot_id src_slot)
{
	struct edhoc_key_slot *dst = &ctx->key_slots[dst_slot];
	struct edhoc_key_slot *src = &ctx->key_slots[src_slot];

	memcpy(dst->key_id, src->key_id, sizeof(dst->key_id));
	dst->present = true;

	ctx->interfaces.platform.zeroize(src->key_id, sizeof(src->key_id));
	src->present = false;
}

void edhoc_key_slot_snapshot(const struct edhoc_context *ctx,
			     enum edhoc_key_slot_id slot, uint8_t *key_id)
{
	memcpy(key_id, ctx->key_slots[slot].key_id,
	       sizeof(ctx->key_slots[slot].key_id));
}

void edhoc_key_slot_restore(struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot, const uint8_t *key_id)
{
	struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];

	memcpy(key_slot->key_id, key_id, sizeof(key_slot->key_id));
	key_slot->present = true;
}

int edhoc_key_slot_release(struct edhoc_context *ctx,
			   enum edhoc_key_slot_id slot)
{
	struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];

	if (!key_slot->present || NULL == ctx->interfaces.crypto.destroy_key) {
		return EDHOC_SUCCESS;
	}

	const int ret = ctx->interfaces.crypto.destroy_key(ctx->user_context,
							   key_slot->key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Destroy key slot %d: %d", (int)slot, ret);
		return ret;
	}

	ctx->interfaces.platform.zeroize(key_slot->key_id,
					 sizeof(key_slot->key_id));
	key_slot->present = false;

	return EDHOC_SUCCESS;
}

int edhoc_key_slot_release_up_to(struct edhoc_context *ctx,
				 enum edhoc_key_slot_id up_to_slot)
{
	for (enum edhoc_key_slot_id slot = EDHOC_KEY_SLOT_SHARED_SECRET;
	     slot < up_to_slot; ++slot) {
		const int ret = edhoc_key_slot_release(ctx, slot);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

	return EDHOC_SUCCESS;
}

int edhoc_key_destroy(struct edhoc_context *ctx, void *key_id)
{
	int ret = EDHOC_SUCCESS;

	if (NULL != ctx->interfaces.crypto.destroy_key) {
		ret = ctx->interfaces.crypto.destroy_key(ctx->user_context,
							 key_id);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Destroy key: %d", ret);
		}
	}

	ctx->interfaces.platform.zeroize(key_id, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return ret;
}
