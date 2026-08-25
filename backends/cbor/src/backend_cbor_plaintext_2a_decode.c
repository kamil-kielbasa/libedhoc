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
#include "backend_cbor_plaintext_2a_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_ead_x(zcbor_state_t *state, struct ead_x *result);
static bool decode_ead(zcbor_state_t *state, struct ead *result);
static bool decode_plaintext_2a(zcbor_state_t *state, struct plaintext_2a *result);


static bool decode_ead_x(
		zcbor_state_t *state, struct ead_x *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).ead_x_ead_label))))
	&& ((*result).ead_x_ead_value_present = ((zcbor_bstr_decode(state, (&(*result).ead_x_ead_value)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_ead(
		zcbor_state_t *state, struct ead *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result).ead_count, (zcbor_decoder_t *)decode_ead_x, state, (&(*result).ead), sizeof(struct ead_x)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_plaintext_2a(
		zcbor_state_t *state, struct plaintext_2a *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).plaintext_2a_C_R_bstr)))) && (((*result).plaintext_2a_C_R_choice = plaintext_2a_C_R_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).plaintext_2a_C_R_int)))
	&& ((((*result).plaintext_2a_C_R_int >= -24)
	&& ((*result).plaintext_2a_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).plaintext_2a_C_R_choice = plaintext_2a_C_R_int_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((*result).plaintext_2a_ead_m_present = ((decode_ead(state, (&(*result).plaintext_2a_ead_m)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_plaintext_2a(
		const uint8_t *payload, size_t payload_len,
		struct plaintext_2a *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_plaintext_2a, sizeof(states) / sizeof(zcbor_state_t), 7);
}
