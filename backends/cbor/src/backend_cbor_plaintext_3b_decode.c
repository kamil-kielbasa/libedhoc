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
#include "backend_cbor_plaintext_3b_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_ead_y(zcbor_state_t *state, struct ead_y *result);
static bool decode_EAD_3(zcbor_state_t *state, struct EAD_3 *result);
static bool decode_plaintext_3b(zcbor_state_t *state, struct plaintext_3b *result);


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

static bool decode_EAD_3(
		zcbor_state_t *state, struct EAD_3 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result).EAD_3_count, (zcbor_decoder_t *)decode_ead_y, state, (&(*result).EAD_3), sizeof(struct ead_y)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_plaintext_3b(
		zcbor_state_t *state, struct plaintext_3b *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((*result).plaintext_3b_present = ((decode_EAD_3(state, (&(*result).plaintext_3b)))), 1));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_plaintext_3b(
		const uint8_t *payload, size_t payload_len,
		struct plaintext_3b *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_plaintext_3b, sizeof(states) / sizeof(zcbor_state_t), 6);
}
