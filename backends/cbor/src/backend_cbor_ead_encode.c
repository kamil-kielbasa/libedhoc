/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_ead_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_ead_x(zcbor_state_t *state, const struct ead_x *input);
static bool encode_ead(zcbor_state_t *state, const struct ead *input);


static bool encode_ead_x(
		zcbor_state_t *state, const struct ead_x *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).ead_x_ead_label))))
	&& (!(*input).ead_x_ead_value_present || zcbor_bstr_encode(state, (&(*input).ead_x_ead_value))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_ead(
		zcbor_state_t *state, const struct ead *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input).ead_count, (zcbor_encoder_t *)encode_ead_x, state, (&(*input).ead), sizeof(struct ead_x)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_ead(
		uint8_t *payload, size_t payload_len,
		const struct ead *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ead, sizeof(states) / sizeof(zcbor_state_t), 6);
}
