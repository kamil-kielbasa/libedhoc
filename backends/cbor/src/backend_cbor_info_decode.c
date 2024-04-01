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
#include "backend_cbor_info_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_info(zcbor_state_t *state, struct info *result);


static bool decode_info(
		zcbor_state_t *state, struct info *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._info_label))))
	&& ((zcbor_bstr_decode(state, (&(*result)._info_context))))
	&& ((zcbor_uint32_decode(state, (&(*result)._info_length)))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_info(
		const uint8_t *payload, size_t payload_len,
		struct info *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 3);

	bool ret = decode_info(states, result);

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
