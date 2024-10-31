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
#include "backend_cbor_message_1_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_suites(zcbor_state_t *state, struct suites_r *result);
static bool decode_ead_x(zcbor_state_t *state, struct ead_x *result);
static bool decode_EAD_1(zcbor_state_t *state, struct EAD_1 *result);
static bool decode_message_1(zcbor_state_t *state, struct message_1 *result);


static bool decode_suites(
		zcbor_state_t *state, struct suites_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 3, &(*result).suites_int_l_int_count, (zcbor_decoder_t *)zcbor_int32_decode, state, (&(*result).suites_int_l_int), sizeof(int32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result).suites_choice = suites_int_l_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result).suites_int)))) && (((*result).suites_choice = suites_int_c), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

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

static bool decode_EAD_1(
		zcbor_state_t *state, struct EAD_1 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result).EAD_1_count, (zcbor_decoder_t *)decode_ead_x, state, (&(*result).EAD_1), sizeof(struct ead_x)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_message_1(
		zcbor_state_t *state, struct message_1 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).message_1_METHOD))))
	&& ((decode_suites(state, (&(*result).message_1_SUITES_I))))
	&& ((zcbor_bstr_decode(state, (&(*result).message_1_G_X))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).message_1_C_I_bstr)))) && (((*result).message_1_C_I_choice = message_1_C_I_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).message_1_C_I_int)))
	&& ((((*result).message_1_C_I_int >= -24)
	&& ((*result).message_1_C_I_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).message_1_C_I_choice = message_1_C_I_int_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((*result).message_1_EAD_1_m_present = ((decode_EAD_1(state, (&(*result).message_1_EAD_1_m)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_message_1(
		const uint8_t *payload, size_t payload_len,
		struct message_1 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_message_1, sizeof(states) / sizeof(zcbor_state_t), 10);
}
