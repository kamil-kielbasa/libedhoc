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
#include "backend_cbor_plaintext_4_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_ead_y(zcbor_state_t *state, const struct ead_y *input);
static bool encode_EAD_4(zcbor_state_t *state, const struct EAD_4 *input);
static bool encode_plaintext_4(zcbor_state_t *state, const struct plaintext_4 *input);


static bool encode_ead_y(
		zcbor_state_t *state, const struct ead_y *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).ead_y_ead_label))))
	&& (!(*input).ead_y_ead_value_present || zcbor_bstr_encode(state, (&(*input).ead_y_ead_value))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_EAD_4(
		zcbor_state_t *state, const struct EAD_4 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input).EAD_4_count, (zcbor_encoder_t *)encode_ead_y, state, (&(*input).EAD_4), sizeof(struct ead_y)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_plaintext_4(
		zcbor_state_t *state, const struct plaintext_4 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((!(*input).plaintext_4_present || encode_EAD_4(state, (&(*input).plaintext_4))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_plaintext_4(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_4 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_plaintext_4, sizeof(states) / sizeof(zcbor_state_t), 6);
}
