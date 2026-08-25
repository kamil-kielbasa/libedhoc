/**
 * \file    edhoc_transcript_hash_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC transcript hash implementation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/cipher_suite.h>

/* EDHOC internal headers: */
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */

/** Longest segment list any transcript hash needs: TH_4 of EDHOC-PSK streams
 *  the previous hash with its byte-string head, ID_CRED_PSK, PLAINTEXT_3B,
 *  CRED_I and CRED_R. */
#define EDHOC_TH_MAX_NR_OF_SEGMENTS (6)

/* Module types and type definitiones -------------------------------------- */

/** \brief One input segment of a multipart hash. */
struct th_segment {
	/** Pointer to the segment bytes. */
	const uint8_t *ptr;
	/** Number of bytes in the segment. */
	size_t len;
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Hash an ordered list of segments through the multipart backend
 *        interface, avoiding a contiguous assembly buffer.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] segments          Ordered input segments.
 * \param nr_of_segments        Number of entries in \p segments.
 * \param[out] hash             Buffer receiving the digest.
 * \param hash_size             Size of the \p hash buffer in bytes.
 * \param[out] hash_length      On success, number of digest bytes written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_hash(const struct edhoc_context *ctx,
		     const struct th_segment *segments, size_t nr_of_segments,
		     uint8_t *hash, size_t hash_size, size_t *hash_length);

/**
 * \brief The public ephemeral value that TH_2 hashes: G_Y, which the Responder
 *        produced itself and the Initiator received.
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] value            On success, the ephemeral value.
 * \param[out] length           On success, its size in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_th_2_ephemeral(const struct edhoc_context *ctx,
			       const uint8_t **value, size_t *length);

/* Static function definitions --------------------------------------------- */

STATIC int comp_hash(const struct edhoc_context *ctx,
		     const struct th_segment *segments, size_t nr_of_segments,
		     uint8_t *hash, size_t hash_size, size_t *hash_length)
{
	void *op = NULL;
	int ret = edhoc_crypto(ctx)->hash_init(ctx->user_context, &op);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	for (size_t i = 0; i < nr_of_segments; ++i) {
		ret = edhoc_crypto(ctx)->hash_update(ctx->user_context, op,
						     segments[i].ptr,
						     segments[i].len);

		if (EDHOC_SUCCESS != ret) {
			goto abort;
		}
	}

	ret = edhoc_crypto(ctx)->hash_finish(ctx->user_context, op, hash,
					     hash_size, hash_length);

	if (EDHOC_SUCCESS != ret) {
		goto abort;
	}

	return EDHOC_SUCCESS;

abort:
	edhoc_crypto(ctx)->hash_abort(ctx->user_context, op);

	return ret;
}

STATIC int comp_th_2_ephemeral(const struct edhoc_context *ctx,
			       const uint8_t **value, size_t *length)
{
	switch (ctx->state.role) {
	case EDHOC_ROLE_INITIATOR:
		*value = ctx->ephemeral.peer.value;
		*length = ctx->ephemeral.peer.length;
		return EDHOC_SUCCESS;
	case EDHOC_ROLE_RESPONDER:
		*value = ctx->ephemeral.own.value;
		*length = ctx->ephemeral.own.length;
		return EDHOC_SUCCESS;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

/* Module interface function definitions ----------------------------------- */

int edhoc_th_compute(struct edhoc_context *ctx,
		     const struct edhoc_th_input *input)
{
	if (NULL == ctx || NULL == input) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* The chain is strictly ordered: the preceding hash must be current. */
	if (EDHOC_TH_STATE_INVALID == input->target ||
	    input->target - 1 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state: %d, %d", ctx->state.th.stage,
			      input->target);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = 0;
	uint8_t previous_head[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };
	/* A segment points into this buffer and the hash is computed after the
	 * switch, so the scope cannot be narrowed to the case block. */
	/* cppcheck-suppress variableScope */
	uint8_t ephemeral_head[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };
	struct th_segment segments[EDHOC_TH_MAX_NR_OF_SEGMENTS] = { 0 };
	size_t nr_of_segments = 0;

	const size_t previous_length = ctx->state.th.length;
	const bool is_psk =
		(EDHOC_METHOD_4 == ctx->negotiation.selected_method);

	switch (input->target) {
	case EDHOC_TH_STATE_1:
		if (NULL == input->message_1 || 0 == input->message_1_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		segments[nr_of_segments] =
			(struct th_segment){ input->message_1,
					     input->message_1_length };
		nr_of_segments += 1;
		break;

	case EDHOC_TH_STATE_2: {
		const uint8_t *ephemeral = NULL;
		size_t ephemeral_length = 0;

		ret = comp_th_2_ephemeral(ctx, &ephemeral, &ephemeral_length);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
			return ret;
		}

		segments[nr_of_segments] = (struct th_segment){
			ephemeral_head,
			edhoc_cbor_bstr_head_write(ephemeral_head,
						   ephemeral_length)
		};
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ ephemeral, ephemeral_length };
		nr_of_segments += 1;

		segments[nr_of_segments] = (struct th_segment){
			previous_head, edhoc_cbor_bstr_head_write(
					       previous_head, previous_length)
		};
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ ctx->state.th.value,
					     previous_length };
		nr_of_segments += 1;
		break;
	}

	case EDHOC_TH_STATE_3:
		if (NULL == input->plaintext || 0 == input->plaintext_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		segments[nr_of_segments] = (struct th_segment){
			previous_head, edhoc_cbor_bstr_head_write(
					       previous_head, previous_length)
		};
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ ctx->state.th.value,
					     previous_length };
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ input->plaintext,
					     input->plaintext_length };
		nr_of_segments += 1;

		/* EDHOC-PSK computes TH_3 = H( TH_2, PLAINTEXT_2A ) and is
		 * complete here, because its message 2 carries no credential;
		 * classic EDHOC computes TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
		 * and goes on to append CRED_R. */
		if (is_psk) {
			break;
		}

		if (NULL == input->credential ||
		    0 == input->credential_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		segments[nr_of_segments] =
			(struct th_segment){ input->credential,
					     input->credential_length };
		nr_of_segments += 1;
		break;

	case EDHOC_TH_STATE_4:
		if (NULL == input->credential ||
		    0 == input->credential_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		if (is_psk) {
			/* TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I,
			 * CRED_R ). PLAINTEXT_3B is empty without EAD_3. */
			if (NULL == input->id_cred ||
			    0 == input->id_cred_length ||
			    NULL == input->peer_credential ||
			    0 == input->peer_credential_length) {
				EDHOC_LOG_ERR("Invalid arguments");
				return EDHOC_ERROR_INVALID_ARGUMENT;
			}

			segments[nr_of_segments] = (struct th_segment){
				previous_head,
				edhoc_cbor_bstr_head_write(previous_head,
							   previous_length)
			};
			nr_of_segments += 1;

			segments[nr_of_segments] =
				(struct th_segment){ ctx->state.th.value,
						     previous_length };
			nr_of_segments += 1;

			segments[nr_of_segments] =
				(struct th_segment){ input->id_cred,
						     input->id_cred_length };
			nr_of_segments += 1;

			if (0 != input->plaintext_length) {
				segments[nr_of_segments] = (struct th_segment){
					input->plaintext,
					input->plaintext_length
				};
				nr_of_segments += 1;
			}

			segments[nr_of_segments] =
				(struct th_segment){ input->credential,
						     input->credential_length };
			nr_of_segments += 1;

			segments[nr_of_segments] = (struct th_segment){
				input->peer_credential,
				input->peer_credential_length
			};
			nr_of_segments += 1;

			break;
		}

		/* TH_4 = H( TH_3, PLAINTEXT_3, CRED_I ). */
		if (NULL == input->plaintext || 0 == input->plaintext_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		segments[nr_of_segments] = (struct th_segment){
			previous_head, edhoc_cbor_bstr_head_write(
					       previous_head, previous_length)
		};
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ ctx->state.th.value,
					     previous_length };
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ input->plaintext,
					     input->plaintext_length };
		nr_of_segments += 1;

		segments[nr_of_segments] =
			(struct th_segment){ input->credential,
					     input->credential_length };
		nr_of_segments += 1;
		break;

	case EDHOC_TH_STATE_INVALID:
	default:
		EDHOC_LOG_ERR("Invalid TH target: %d", input->target);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	const size_t hash_length =
		edhoc_selected_cipher_suite(ctx)->hash_length;

	ctx->state.th.length = hash_length;

	size_t written = 0;
	ret = comp_hash(ctx, segments, nr_of_segments, ctx->state.th.value,
			ctx->state.th.length, &written);

	if (EDHOC_SUCCESS != ret || hash_length != written) {
		EDHOC_LOG_ERR("TH_%d hash: %d, %zu, %zu", input->target, ret,
			      hash_length, written);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->state.th.stage = input->target;

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "transcript hash");

	return EDHOC_SUCCESS;
}

int edhoc_th_encoded_length(size_t th_length, size_t *length)
{
	if (0 == th_length || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	*length = th_length + edhoc_cbor_bstr_head_length(th_length);

	return EDHOC_SUCCESS;
}
