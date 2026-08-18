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
#include "backend_cbor_connection_identifier_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_connection_identifier(zcbor_state_t *state, struct connection_identifier_r *result);


static bool decode_connection_identifier(
		zcbor_state_t *state, struct connection_identifier_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).connection_identifier_bstr)))) && (((*result).connection_identifier_choice = connection_identifier_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).connection_identifier_int)))
	&& ((((*result).connection_identifier_int >= -24)
	&& ((*result).connection_identifier_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).connection_identifier_choice = connection_identifier_int_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_connection_identifier(
		const uint8_t *payload, size_t payload_len,
		struct connection_identifier_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_connection_identifier, sizeof(states) / sizeof(zcbor_state_t), 1);
}
