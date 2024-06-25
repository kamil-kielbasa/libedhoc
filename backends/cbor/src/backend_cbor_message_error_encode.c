/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_message_error_encode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_suites(zcbor_state_t *state, const struct suites_ *input);
static bool encode_repeated_message_error_ERR_INFO(zcbor_state_t *state, const struct message_error_ERR_INFO_ *input);
static bool encode_message_error(zcbor_state_t *state, const struct message_error *input);


static bool encode_suites(
		zcbor_state_t *state, const struct suites_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((*input)._suites_choice == _suites__int) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input)._suites__int_int_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input)._suites__int_int), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: (((*input)._suites_choice == _suites_int) ? ((zcbor_int32_encode(state, (&(*input)._suites_int))))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_message_error_ERR_INFO(
		zcbor_state_t *state, const struct message_error_ERR_INFO_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((*input)._message_error_ERR_INFO_choice == _message_error_ERR_INFO_tstr) ? ((zcbor_tstr_encode(state, (&(*input)._message_error_ERR_INFO_tstr))))
	: (((*input)._message_error_ERR_INFO_choice == _message_error_ERR_INFO__suites) ? ((encode_suites(state, (&(*input)._message_error_ERR_INFO__suites))))
	: (((*input)._message_error_ERR_INFO_choice == _message_error_ERR_INFO_bool) ? ((zcbor_bool_put(state, (true))))
	: false)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_message_error(
		zcbor_state_t *state, const struct message_error *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input)._message_error_ERR_CODE))))
	&& zcbor_present_encode(&((*input)._message_error_ERR_INFO_present), (zcbor_encoder_t *)encode_repeated_message_error_ERR_INFO, state, (&(*input)._message_error_ERR_INFO)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_message_error(
		uint8_t *payload, size_t payload_len,
		const struct message_error *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 2);

	bool ret = encode_message_error(states, input);

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
