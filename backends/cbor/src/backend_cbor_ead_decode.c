/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "backend_cbor_ead_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_ead(zcbor_state_t *state, struct ead *result);
static bool decode_ead(zcbor_state_t *state, struct ead_ *result);


static bool decode_repeated_ead(
		zcbor_state_t *state, struct ead *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._ead_label))))
	&& zcbor_present_decode(&((*result)._ead_value_present), (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._ead_value)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_ead(
		zcbor_state_t *state, struct ead_ *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result)._ead_count, (zcbor_decoder_t *)decode_repeated_ead, state, (&(*result)._ead), sizeof(struct ead)));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_ead(
		const uint8_t *payload, size_t payload_len,
		struct ead_ *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 6);

	bool ret = decode_ead(states, result);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	if (!ret) {
		int err = zcbor_pop_error(states);

		zcbor_print("Return error: %d\r\n", err);
		return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
	}
	return ZCBOR_SUCCESS;
}
