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
#include "backend_cbor_message_error_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_suites(zcbor_state_t *state, struct suites_r *result);
static bool decode_repeated_message_error_ERR_INFO(zcbor_state_t *state, struct message_error_ERR_INFO_r *result);
static bool decode_message_error(zcbor_state_t *state, struct message_error *result);


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

static bool decode_repeated_message_error_ERR_INFO(
		zcbor_state_t *state, struct message_error_ERR_INFO_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result).message_error_ERR_INFO_tstr)))) && (((*result).message_error_ERR_INFO_choice = message_error_ERR_INFO_tstr_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_suites(state, (&(*result).message_error_ERR_INFO_suites_m)))) && (((*result).message_error_ERR_INFO_choice = message_error_ERR_INFO_suites_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((zcbor_bool_expect(state, (true)))) && (((*result).message_error_ERR_INFO_choice = message_error_ERR_INFO_bool_c), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_message_error(
		zcbor_state_t *state, struct message_error *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).message_error_ERR_CODE))))
	&& zcbor_present_decode(&((*result).message_error_ERR_INFO_present), (zcbor_decoder_t *)decode_repeated_message_error_ERR_INFO, state, (&(*result).message_error_ERR_INFO)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_message_error(
		const uint8_t *payload, size_t payload_len,
		struct message_error *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_message_error, sizeof(states) / sizeof(zcbor_state_t), 2);
}
