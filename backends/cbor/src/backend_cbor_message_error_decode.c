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
#include "backend_cbor_message_error_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_suites(zcbor_state_t *state, struct suites_ *result);
static bool decode_repeated_message_error_ERR_INFO(zcbor_state_t *state, struct message_error_ERR_INFO_ *result);
static bool decode_message_error(zcbor_state_t *state, struct message_error *result);


static bool decode_suites(
		zcbor_state_t *state, struct suites_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 3, &(*result)._suites__int_int_count, (zcbor_decoder_t *)zcbor_int32_decode, state, (&(*result)._suites__int_int), sizeof(int32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result)._suites_choice = _suites__int), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result)._suites_int)))) && (((*result)._suites_choice = _suites_int), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_message_error_ERR_INFO(
		zcbor_state_t *state, struct message_error_ERR_INFO_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result)._message_error_ERR_INFO_tstr)))) && (((*result)._message_error_ERR_INFO_choice = _message_error_ERR_INFO_tstr), true))
	|| (zcbor_union_elem_code(state) && (((decode_suites(state, (&(*result)._message_error_ERR_INFO__suites)))) && (((*result)._message_error_ERR_INFO_choice = _message_error_ERR_INFO__suites), true)))
	|| (zcbor_union_elem_code(state) && (((zcbor_bool_expect(state, (true)))) && (((*result)._message_error_ERR_INFO_choice = _message_error_ERR_INFO_bool), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_message_error(
		zcbor_state_t *state, struct message_error *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._message_error_ERR_CODE))))
	&& zcbor_present_decode(&((*result)._message_error_ERR_INFO_present), (zcbor_decoder_t *)decode_repeated_message_error_ERR_INFO, state, (&(*result)._message_error_ERR_INFO)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_message_error(
		const uint8_t *payload, size_t payload_len,
		struct message_error *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 2);

	bool ret = decode_message_error(states, result);

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
