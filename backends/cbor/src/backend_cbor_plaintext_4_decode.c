/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "backend_cbor_plaintext_4_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_ead_y(zcbor_state_t *state, struct ead_y *result);
static bool decode_EAD_4(zcbor_state_t *state, struct EAD_4 *result);
static bool decode_plaintext_4(zcbor_state_t *state, struct plaintext_4 *result);


static bool decode_ead_y(
		zcbor_state_t *state, struct ead_y *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).ead_y_ead_label))))
	&& ((*result).ead_y_ead_value_present = ((zcbor_bstr_decode(state, (&(*result).ead_y_ead_value)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_EAD_4(
		zcbor_state_t *state, struct EAD_4 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result).EAD_4_count, (zcbor_decoder_t *)decode_ead_y, state, (&(*result).EAD_4), sizeof(struct ead_y)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_plaintext_4(
		zcbor_state_t *state, struct plaintext_4 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((*result).plaintext_4_present = ((decode_EAD_4(state, (&(*result).plaintext_4)))), 1));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_plaintext_4(
		const uint8_t *payload, size_t payload_len,
		struct plaintext_4 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_plaintext_4, sizeof(states) / sizeof(zcbor_state_t), 6);
}
